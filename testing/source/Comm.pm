
=head1 NAME

Globus::Testing::Comm - Communicate with remote perl processes

=cut

package Globus::Testing::Comm;

use Socket;
use Carp;
use Sys::Hostname;
use FileHandle;
use strict 'vars';
use vars qw/$AUTOLOAD %ENV/;
use POSIX "sys_wait_h";

=head1 SYNOPSIS

 use Globus::Testing::Comm;

 $comm = new Globus::Testing::Comm();
 $comm = new Globus::Testing::Comm($host,$port);
 $comm->start_server($client_count);
 $comm->put($key,$value)
 $comm->fence($timeout)
 $value = $comm->get($key)
 $comm->stop_server()

=head1 DESCRIPTION

=head2 sub new([$host,$port])

This function creates a new Comm object. The Comm object is assigned a
client id based on the environment variable C<CLIENT_ID>. If this
variable is not set the id 1 is assumed. 

B<Arguments:>

=over 8

=item * I<host> 

Optional argument specifying the hostname of the server. If this
argument is not given, the environment variable C<COMM_SERVER_HOST> is
checked. Should this variable be empty the local hostname is used.  

=item * I<port> 

Optional argument specifying the port of the server. If this argument
is not given the environment variable C<COMM_SERVER_PORT> is
checked. Should this variable be empty the port is set to 
C<32768 + $PID%32768>. 

=back

=cut
sub new($) 
{
   my $type = shift;
   my $host = undef;
   my $port = undef;
   my $client_id = $::ENV{CLIENT_ID} || 1;
   my $pid = $$;
   
   #print "$pid\n";

   if(@_)
   {
      $host=shift;
      $port=shift;
   }
   else
   {
      $host = $::ENV{COMM_SERVER_HOST} || hostname();
      $port = $::ENV{COMM_SERVER_PORT} || 32768 + $pid%32768;
   }

   #print "Host: $host Port: $port\n";

   my $self={
	     hostname => $host,
	     port => $port,
	     ip => inet_aton($host),
	     data => {},
	     fence_array => [],
	     pid => undef,
	     register => 1,
	     client_id => $client_id,
	    };
   return bless $self,$type;
}

=head2 sub start_server($client_count)

This function forks off a Comm server on the host/port specified by the
Comm object.

B<Arguments:>

=over 8

=item * I<client_count>

The number of clients the server is going to have. This is needed for
the fence function.

=back

=cut

sub start_server($$)
{
   my $self = shift;
   my $client_count = shift;
   my $type = ref($self) || croak "$self is not an object";
   my $proto = getprotobyname('tcp');
   my $pid = undef;
   my $server = FileHandle->new();

   socket($server, PF_INET, SOCK_STREAM, $proto) || croak "socket: $!";
   setsockopt($server, SOL_SOCKET, SO_REUSEADDR, pack("l",1)) || 
      croak "setsockopt: $!";
   bind($server, sockaddr_in($self->{"port"}, INADDR_ANY)) || croak "bind: $!";
   listen($server,SOMAXCONN) || croak "listen: $!";

   defined($pid = fork) || croak "Unable to fork server: $!";

   if($pid)
   {
       $self->{"pid"}=$pid;
       close($server);
       return;
   }


   # In the child now:

   my $key;
   my $value;
   my $offset = 0;
   my $client = FileHandle->new();
   my $i = 0;
   my $fd;

   while(1)
   {

    ACCEPT_LOOP:
      while(accept($client,$server))
      {
#	 print "got connection\n";
	 STDOUT->flush();
	 while(<$client>)
	 {
#	    print "$_\n";
#	    STDOUT->flush();
	  SWITCH:
	    {
	       /^get (.+)/ && do { #print "Getting key $1\n Returning $self->{data}->{$1}\n ";
#				   print keys(%{$self->{"data"}}),"\n";
#				   STDOUT->flush();
				   print $client $self->{"data"}->{$1};
				   close($client);
				   $client=FileHandle->new();
				   last ACCEPT_LOOP;
			       };
	       /^fence (.+)/ && do { $self->{"fence_array"}->[$1] &&
					croak "Fence already set for $1";
				     $self->{"fence_array"}->[$1]=$client;
				     $client = FileHandle->new();
				     $i++;
				     if( $i == $client_count)
				     {
					for($i=1;
					    $i <= $client_count;
					    $i++)
					{
					   $fd = $self->{fence_array}->[$i];
					   print $fd "clear";
					   close($fd);
					   $self->{fence_array}->[$i]=undef;
					}
					$i=0;
				     }
				     last ACCEPT_LOOP;
				  };
	       /^put (\w+) / && do {#print "$_\n";
				    $key=$1;
				    $value=substr($_,5+length($1));
				    last SWITCH;};
	       $value.=$_; #add current line to value
	    }
	 }
#	 print "setting $key to $value\n";
	 ($self->{"data"})->{$key}=$value;
	 close($client);
	 $client=FileHandle->new();
      }
   }
}


=head2 sub put($key,$value)

This function sends the key/value pair to the server specified by the
Comm object it is acting on. 

B<Arguments:>

=over 8

=item * I<key>

The key (or if you want variable) that is going to be sent.

=item * I<value>

The value that is going to be sent.

=back

=cut


sub put($$$)
{
   my $self = shift;
   my $key = shift;
   my $value = shift;
   my $server = FileHandle->new();
   my $type = ref($self) || croak "$self is not an object";
   my $proto = getprotobyname('tcp');

   socket($server, PF_INET, SOCK_STREAM, $proto) || croak "socket: $!";

   connect($server,sockaddr_in($self->{"port"},
			      $self->{"ip"})) || croak "connect: $!";
   print $server "put ",$key," ",$value;
   close($server);
   return;
}

=head2 sub fence($timeout)

This function sends a fence request to the server. The function
returns once all clients that are registered with the server have done
likewise. This is used for synchronization.

B<Arguments:>

=over 8

=item * I<timeout>

An optional argument specifying the number of seconds to wait on the
fence to succeed. If the fence does not succeed with in the given time
the program is aborted.

=back

=cut


sub fence($;$)
{
   my $self = shift;
   my $timeout = shift || 0;
   my $type = ref($self) || croak "$self is not an object";
   my $proto = getprotobyname('tcp');
   my $server = FileHandle->new();

   sub catch_alarm
   {
      croak "Fence timed out";
   }

   $SIG{ALRM} = \&catch_alarm;

   socket($server, PF_INET, SOCK_STREAM, $proto) || croak "socket: $!";

   connect($server,sockaddr_in($self->{"port"},
			      $self->{"ip"})) || croak "connect: $!";
   print $server "fence $self->{client_id}\n";
   
   $server->flush();

   alarm($timeout);

   $_=<$server>;
   
   alarm(0);

   close($server);
   return;
}

=head2 sub get($key)

This function retreives the value corresponding to C<key> from the
server. If the key does not exist on the server, an empty string is
returned 

B<Arguments:>

=over 8

=item * I<key>

The key for which the value is going to be retreived.

=back

=cut


sub get($$)
{
   my $self = shift;
   my $key = shift;
   my $type = ref($self) || croak "$self is not an object";
   my $proto = getprotobyname('tcp');
   my $value="";
   my $server=FileHandle->new();

   socket($server, PF_INET, SOCK_STREAM, $proto) || croak "socket: $!";

   connect($server,sockaddr_in($self->{"port"},
			      $self->{"ip"}))|| croak "connect: $!";
   print $server "get $key\n";

   $server->flush();

   while(<$server>)
   {
      $value.=$_;
   }
   close($server);
   return $value; 
}

=head2 sub stop_server()

Kills the server associated with the objection this function is
invoked on.

B<Arguments:>

=over 8

=item * None

=back

=cut

sub stop_server($)
{
   my $self = shift;
   my $type = ref($self) || croak "$self is not an object";

   kill 9, $self->{"pid"};
   return;
}

sub AUTOLOAD 
{
   my $self = shift;
   my $type = ref($self) || croak "$self is not an object";
   my $name = $::AUTOLOAD;

   return undef if !defined($name);

   $name =~ s/.*://;

   if(@_)
   {
      if(ref($self->{$name}) eq "ARRAY")
      {
	 return push(@{$self->{$name}},@_);
      }
      else
      {
	 return $self->{$name} = shift;
      }
   }
   else
   {
      return $self->{$name};
   }
}

sub DESTROY
{
   my $self = shift;
   my $type = ref($self) || croak "$self is not an object";

   $self->stop_server();
}

=head2 SEE ALSO

L<Globus::Testing::Startup|Globus::Testing::Startup>

=cut

1;
