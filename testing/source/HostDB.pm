=head1 NAME

Globus::Testing::HostDB - Host capability configuration

=cut

package Globus::Testing::HostDB;

use Carp;
use Globus::Testing::Host;
use strict 'vars';
use vars qw/$AUTOLOAD/;


=head1 SYNOPSIS

 use Globus::Testing::HostDB;

 $hostdb = new Globus::Testing::HostDB;
 $hostdb->readdb($filename);
 $hostdb->querydb($query);

=head1 DESCRIPTION

The C<Globus::Testing::HostDB> object is used to import a user-defined set of
host configuration information from a file to be used when running a progam
using the L<Globus::Testing::Startup|Globus::Testing::Startup> object.

=head2 sub new()

This function creates a new HostDB object.

B<Arguments:>

=over 8

=item * None

=back

=cut
sub new 
{
   my $type=shift;
   my $self={};
   return bless $self,$type;
}

=head2 sub readdb($filename)

This function reads a given host database, parses it and stores it in
the given object. Each host entry of the database must be of the form:

 <hostname>
 {
	<key>:<value><,value>*
	<jobmanager_name>
	{
		<jobmanager_key>:<space>*<value>
	}
 }

Currently valid keys are:

=over 8

=item * I<execution>

Specifies the remote execution methods supported by the host. Possible
values are: C<rsh>, C<ssh>, C<local>,  and C<gram> 

=item * I<jobmanagers>

A list of jobmanager available on the host. Currently recognized
values are: C<default>, C<fork> and C<loadleveler>. There must be a
jobmanager section for each jobmanager listed. [Optional] 

=item * I<capabilities>

A list of capabilities the host has. Currently recognized values are:
C<mpi>, C<script> and C<perl>.  

=item * I<perl>

The full path to the perl executable on the host.

=item * I<directory>

The full path to base testing directory for the host. [Optional]

=item * I<arch>

A string (a la C<config.guess>) identifying the architecture of the
host. [Optional] 

=back

Currently valid jobmanager keys are:

=over 8

=item * I<contact>

The full contact string for the gatekeeper/jobmanager.

=item * I<queue>

The queue RSL parameter.

=item * I<project>

The project RSL parameter.

=item * I<maxtime>

The maxtime RSL parameter.

=back

More keys will likely be added in the future.

B<Arguments:>

=over 8

=item * I<filename>

The name of the file containing the host database.

=back

=cut
sub readdb
{
   my $self  = shift;
   my $type  = ref($self) || croak "$self is not an object";
   my $FILE  = shift;
   my $level = 0;
   my $hostname = "";
   my $hostobj;
   my $jobmanager;
   my $arg;

   open FILE,"<$FILE" || croak "Couldn't open file $FILE: $!";
   
   while(<FILE>)
   {
    SWITCH:
      {
	 /\{/ && do {$level++;};
	 /\}/ && do {$level--;};
	 /execution:/i && do 
	 {
	    $level == 1 || croak "Wrong level";
	    /ssh/i  && ($self->$hostname())->execution("ssh");
	    /rsh/i  && ($self->$hostname())->execution("rsh");
	    /gram/i && ($self->$hostname())->execution("gram");
	    /local/i && ($self->$hostname())->execution("local");
	    last SWITCH;
	 };
	 /jobmanagers:/i && do 
	 {
	    $level == 1 || croak "Wrong level";
	    /default/i  && ($self->$hostname())->jobmanagers("default");
	    /fork/i  && ($self->$hostname())->jobmanagers("fork");
	    /loadleveler/i  && 
	       ($self->$hostname())->jobmanagers("loadleveler");
	    last SWITCH;
	 };
	 /capabilities:/i && do 
	 {
	    $level == 1 || croak "Wrong level";
	    /mpi/i    && ($self->$hostname())->capabilities("mpi");
	    /perl/i    && ($self->$hostname())->capabilities("perl");
	    /script/i && ($self->$hostname())->capabilities("script");
	    last SWITCH;
	 };
	 /perl:\s*(.+)/i && do 
	 {
	    $level == 1 || croak "Wrong level";
	    $arg = $1;
	    ($self->$hostname())->perl("$arg");
	    last SWITCH;
	 };

	 /directory:\s*(.+)/i && do 
	 {
	    $level == 1 || croak "Wrong level";
	    $arg = $1;
	    $arg =~ s/\s//g;
	    ($self->$hostname())->directory("$arg");
	    last SWITCH;
	 };

	 /arch:\s*(.+)/i && do 
	 {
	    $level == 1 || croak "Wrong level";
	    $arg = $1;
	    ($self->$hostname())->arch("$arg");
	    last SWITCH;
	 };

	 # determine which jobmanager section we are parsing

	 /default/i && do
	 {
	    $jobmanager="default";
	    (($self->$hostname())->$jobmanager(Globus::Testing::Gram->new()));
	    last SWITCH;  
	 };
	 /loadleveler/i && do
	 {
	    $jobmanager="loadleveler";
	    (($self->$hostname())->$jobmanager(Globus::Testing::Gram->new()));
	    last SWITCH;  
	 };
	 /fork/i && do
	 {
	    $jobmanager="fork";
	    (($self->$hostname())->$jobmanager(Globus::Testing::Gram->new()));
	    last SWITCH;  
	 };

	 # parse gram variables

	 /contact:\s*(".+")/i && do 
	 {
	    $level == 2 || croak "Wrong level";
	    $arg = $1;
	    (($self->$hostname())->$jobmanager())->contact($arg);
	    last SWITCH;
	 };
	 /queue:\s*(.+)/i && do 
	 {
	    $level == 2 || croak "Wrong level";
	    $arg = $1;
	    (($self->$hostname())->$jobmanager())->queue($arg);
	    last SWITCH;
	 };
	 /project:\s*(.+)/i && do 
	 {
	    $level == 2 || croak "Wrong level";
	    $arg = $1;
	    (($self->$hostname())->$jobmanager())->project($arg);
	    last SWITCH;
	 };
	 /maxtime:\s*(.+)/i && do 
	 {
	    $level == 2 || croak "Wrong level";
	    $arg=$1;
	    (($self->$hostname())->$jobmanager())->maxtime($arg);
	    last SWITCH;
	 };
	 /([\w.-]+)/ && do
	 {
	    $hostname = $1;
	    $level == 0 || croak "Wrong level";
	    $hostobj=Globus::Testing::Host->new();
	    $self->$hostname($hostobj);
	    last SWITCH;
	 };
      }
   }
   close FILE;
}

=head2 sub querydb($query)

This function queries the database for hosts matching certain
criteria. 

B<Arguments:>

=over 8

=item * I<query>

Query must be a hash reference. Valid keys are:

=over 8

=item * I<hosts>

Instead of running the query against all hosts in the database only
use the hosts specified. [Optional]

=item * I<execution>

Check for hosts that support at least one of the listed remote
execution methods

=item * I<capabilities>

Check for hosts that have all of the listed capabilities. [Optional]

=item * I<jobmanagers>

Check for hosts that have all of the listed jobmanagers. [Optional]

=back

=back

=cut
sub querydb
{
   my $self  = shift;
   my $type  = ref($self) || croak "$self is not an object";
   my $query = shift;
   my @matching_keys=();

   foreach ($query->{"hosts"} || keys(%{$self}))
   {
      if(exists($self->{$_}) && $self->{$_}->match($query))
      {
	 push(@matching_keys,$_);
      }
   }
   
   return @matching_keys;
}

sub AUTOLOAD 
{
   my $self = shift;
   my $type = ref($self) || croak "$self is not an object";
   my $name = $AUTOLOAD;
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

sub print_obj
{
   my $self = shift;
   my $type = ref($self) || croak "$self is not an object";


   foreach (keys(%{$self}))
   {
      print "Hostname: $_\n\n";
      ($self->{$_})->print_obj();
      print "\n";
   }
}

=head1 SEE ALSO

L<Globus::Testing::Startup|Globus::Testing::Startup>

=cut

1;
