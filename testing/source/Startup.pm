package Globus::Testing::Startup;

use Globus::Testing::Comm;
use Globus::Testing::HostDB;

use Carp;
use Cwd;
use strict 'vars';
use vars qw/$AUTOLOAD $PID %ENV/;

=pod

=head1 NAME

Globus::Testing::Startup - Start a job on or stage files to/from a remote resource.

=head1 SYNOPSIS

 $startup = Globus::Testing::Startup->new([options....])
 $startup->stage($local_file, $remote_file)
 $startup->stageback($remote_file, $local_file)
 $startup->startup($executable, $args)

=head1 DESCRIPTION

The Globus::Testing::Startup object provides an easy way to start jobs on remote
machines using a variety of services. Additionally, files may be transferred
to or from a remote machine. The machine capabilities are defined in 
a Globus::Testing::HostDB object. A Globus:Comm object may be associated with a
Globus::Testing::Startup object to enable communication between remote jobs and
the perl script which launched them.

=head2 sub Globus::Testing::Startup->new()

This function creates a new Startup object.

B<Arguments:>

The arguments to this constructor are a hash of values. The defined hash names
are:

=over 8

=item * I<hosts>

An array of possible hosts to execute on. Note that only one of the
hosts is actually going to be used. May be empty. See L<Globus::Testing::HostDB>
for details. 

=item * I<execution> 

An array of desired remote execution methods. See HostDB documentation
for valid values. If this argument is undefined, C<['local', 'ssh','rsh',
'gram']> will be used.

=item * I<capabilities>

A list of desired capabilities.  See HostDB documentation for valid
values. If no special capabilities are required use C<undef>. 

=item * I<jobmanagers>

A list of desired jobmanagers. See HostDB documentation for valid
values. If no jobmanagers are required use undef. Using undef will set
this variable to C<default>. 

=item * I<directory>

The directory to run in. If the host specifies a base directory, the
directory will be taken to be relative to the host one. May be
undefined. 

=item * I<username>

The username to use for remote startup. If not defined it is set to
the current user's name.

=item * I<env>

A hash reference containing key-value pairs a la C<%ENV>. May be undefined.

=item * I<comm>

A Comm object.

=item * I<hostdb>

A HostDB object.

=back

=cut
sub new($%)
{
   my $class = shift;
   my $self = {};
   my %ref = @_;

   # Set defaults:
   $ref{hosts} = [] unless $ref{hosts};
   $ref{execution} = ['local', 'ssh', 'rsh', 'gram' ] unless($ref{execution}); 
   $ref{capabilities} = [] unless($ref{capabilities});
   $ref{jobmanagers} = ['default'] unless($ref{jobmanagers});
   $ref{directory} = "." unless($ref{directory});
   $ref{username} = $ENV{USER} unless($ref{username});
   $ref{env} = {} unless($ref{env});

   if($ref{comm})
   {
      $ref{env}->{COMM_SERVER_HOST} = $ref{comm}->{hostname};
      $ref{env}->{COMM_SERVER_PORT} = $ref{comm}->{port};
      $ref{comm}->{register}++;
      $ref{env}->{CLIENT_ID} = $ref{comm}->{register};
   }

   $ref{hostdb} || croak "No HostDB object specified";

   $self= {
	     hosts => $ref{hosts},
	     execution => $ref{execution},
	     capabilities => $ref{capabilities},
	     jobmanagers => $ref{jobmanagers},
	     directory => $ref{directory},
	     username => $ref{username},
	     env => $ref{env},
	     hostdb => $ref{hostdb}
	    };
   return bless $self, $class;
}

=head2 sub stage($local_file,$remote_file)

This function copies a specified file to the remote host the Startup
object points to. It is assumed that this can be done without user
interaction (no passwords required etc) and the the excutable used for
the copying (rcp, scp, globusrun)is in the path. The actual copying is
done based on the execution method specified in the object. The target
directory is resolved as follows: 

 <host base dir>/<test dir>
 <home>/<host base dir>/<test dir>
 <test dir>
 <home>/<test dir>
 <home>

Also note that the target directory is assumed to exist.

B<Arguments:>

=over 8

=item * I<local_file> 

The file to copy. If this file can not be found and if the remote host
definition has a arch field, file.<arch> is copied.

=item * I<remote_file> 

The target of the copy. If this argument is not given, source and
target are assumed to be the same.

=back

=cut
sub stage($$)
{
   my $self = shift;
   my $local = shift;
   my $remote = shift || $local;
   my $execution;
   my @result;
   my $method;
   my $arch;
   my $hostdb = $self->{"hostdb"};

   @result = $hostdb->querydb($self);

   @result || croak "Could not find any hosts that met requirements";

   $arch=$hostdb->{$result[0]}->arch();

   (-r $local) ||
      ($arch && (-r ($local.=".$arch"))) ||
	 croak "Could not find $local";

   $execution = ($self->{"execution"})->[0];
   
   $method = "stage_$execution";

   $self->$method($result[0],$local,$remote);
   
   return;  
}


sub stage_ssh($$$$)
{
   my $self = shift;
   my $hostname = shift;
   my $scp_from = shift;
   my $remote = shift;
   my $user = $self->{"username"};
   my $base_dir = $self->{"hostdb"}->{$hostname}->directory();
   my $test_dir = $self->{"directory"};
   my $scp_to;

   # should I check for $scp_from.$arch????

   if($base_dir)
   {
      $scp_to="$user\@$hostname:$base_dir/$test_dir/$remote";
   }
   else
   {
      if($test_dir)
      {
	 $scp_to="$user\@$hostname:$test_dir/$remote";
      }
      else
      {
	 $scp_to="$user\@$hostname:$remote";
      }
   }

   system('scp','-p','-B',$scp_from,$scp_to) == 0
      or croak "scp failed";
}

sub stage_rsh($$$$)
{
   my $self = shift;
   my $hostname = shift;
   my $rcp_from = shift;
   my $remote = shift;
   my $user = $self->{"username"};
   my $base_dir = $self->{"hostdb"}->{$hostname}->directory();
   my $test_dir = $self->{"directory"};
   my $rcp_to;


   if($base_dir)
   {
      $rcp_to="$user\@$hostname:$base_dir/$remote";
   }
   else
   {
      if($test_dir)
      {
	 $rcp_to="$user\@$hostname:$test_dir/$remote";
      }
      else
      {
	 $rcp_to="$user\@$hostname:$remote";
      }
   }

   system('scp','-p','-B','-q',$rcp_from,$rcp_to) == 0
      or croak "rcp failed";

}

sub stage_gram($$$$)
{
   my $self = shift;
   my $hostname = shift;
   my $gass_from = shift;
   my $remote = shift;
   my $pwd = cwd();
   my $jobmanager = ($self->{"jobmanagers"})->[0];
   my $user = $self->{"username"};
   my $contact = ($self->{"hostdb"}->{$hostname}->$jobmanager())->contact();
   my $base_dir = $self->{"hostdb"}->{$hostname}->directory();
   my $test_dir = $self->{"directory"};
   my $gass_to;
   my $rsl;

   $contact=$hostname unless($contact);
   $contact =~ s/\"//g;

   if($base_dir)
   {
      if($base_dir =~ /^\s*\//)
      {
	 $gass_to="file:$base_dir/$test_dir/$remote";
      }
      else
      {
	 $gass_to="file:\$(HOME)/$base_dir/$test_dir/$remote";
      }
   }
   else
   {
      if($test_dir)
      {
	 if($test_dir =~ /^\s*\//)
	 {
	    $gass_to="file:$test_dir/$remote";
	 }
	 else
	 {
	    $gass_to="file:\$(HOME)/$test_dir/$remote";
	 }
      }
      else
      {
	 $gass_to="file:\$(HOME)/$remote";
      }
   }


   if($gass_from !~ /^\s*\//) #if not absolute path
   {
      $gass_from="$pwd/$gass_from";
   }


   $rsl=" &(executable=\$(GLOBUS_TOOLS_PREFIX)#/bin/globus-url-copy)(arguments=\$(GLOBUSRUN_GASS_URL)#$gass_from $gass_to)";
   system('globusrun',"-s","-r",$contact,$rsl) == 0
      or croak "globusrun failed";

}

sub stage_local($$$$)
{
   my $self = shift;
   my $hostname = shift;
   my $cp_from = shift;
   my $remote = shift;
   my $user = $self->{"username"};
   my $base_dir = $self->{"hostdb"}->{$hostname}->directory();
   my $test_dir = $self->{"directory"};
   my $cp_to;

   # should I check for $cp_from.$arch????

   if($base_dir)
   {
      $cp_to="$base_dir/$test_dir/$remote";
   }
   else
   {
      if($test_dir)
      {
	 $cp_to="$test_dir/$remote";
      }
      else
      {
	 $cp_to="$remote";
      }
   }

   system('cp',$cp_from,$cp_to) == 0
      or croak "cp failed";
}


=pod

=head2 sub stageback($remote_file,$local_file)

This function copies a specified file from the remote host the Startup
object points to. It is assumed that this can be done without user
interaction (no passwords required etc) and the the excutable used for
copying (rcp, scp, globusrun) is in the path. The actual copying is
done based on the execution method specified in the object. The remote
directory is resolved as follows: 

 <host base dir>/<test dir>
 <home>/<host base dir>/<test dir>
 <test dir>
 <home>/<test dir>
 <home>

Also note that the target directory is assumed to exist.

B<Arguments:>

=over 8

=item * I<remote_file> 

The file to copy. If this file can not be found and if the remote host
definition has a arch field, file.<arch> is copied.

=item * I<local_file> 

The target of the copy. If this argument is not given, source and
target are assumed to be the same.

=back

=cut


sub stageback($$)
{
   my $self = shift;
   my $remote = shift;
   my $local = shift || $remote;
   my $execution;
   my @result;
   my $method;
   my $arch;
   my $hostdb = $self->{"hostdb"};

   @result = $hostdb->querydb($self);

   @result || croak "Could not find any hosts that met requirements";

   $arch=$hostdb->{$result[0]}->arch();

   $execution = ($self->{"execution"})->[0];
   
   $method = "stageback_$execution";

   $self->$method($result[0],$remote,$local);
   
   return;
}

sub stageback_ssh($$$$)
{
   my $self = shift;
   my $hostname = shift;
   my $rcp_from = shift;
   my $local = shift;
   my $user = $self->{"username"};
   my $base_dir = $self->{"hostdb"}->{$hostname}->directory();
   my $test_dir = $self->{"directory"};


   # should I check for $scp_from.$arch????

   if($base_dir)
   {
      $rcp_from="$user\@$hostname:$base_dir/$rcp_from";
   }
   else
   {
      if($test_dir)
      {
	 $rcp_from="$user\@$hostname:$test_dir/$rcp_from";
      }
      else
      {
	 $rcp_from="$user\@$hostname:$rcp_from";
      }
   }

   system('scp','-B','-p',$rcp_from,$local) == 0
      or croak "rcp failed";

}

sub stageback_rsh($$$$)
{
   my $self = shift;
   my $hostname = shift;
   my $remote = shift;
   my $local = shift;
   my $user = $self->{"username"};
   my $base_dir = $self->{"hostdb"}->{$hostname}->directory();
   my $test_dir = $self->{"directory"};
   my $rcp_from;


   # should I check for $scp_from.$arch????

   if($base_dir)
   {
      $rcp_from="$user\@$hostname:$base_dir/$remote";
   }
   else
   {
      if($test_dir)
      {
	 $rcp_from="$user\@$hostname:$test_dir/$remote";
      }
      else
      {
	 $rcp_from="$user\@$hostname:$remote";
      }
   }

   system('rcp','-p',$rcp_from,$local) == 0
      or croak "rcp failed";

}

sub stageback_gram($$$$)
{
   my $self = shift;
   my $hostname = shift;
   my $gass_from = shift;
   my $local = shift;
   my $jobmanager = ($self->{"jobmanagers"})->[0];
   my $user = $self->{"username"};
   my $contact = ($self->{"hostdb"}->{$hostname}->$jobmanager())->contact();
   my $base_dir = $self->{"hostdb"}->{$hostname}->directory();
   my $test_dir = $self->{"directory"};
   my $gass_to;
   my $rsl;

   $contact=$hostname unless($contact);
   $contact =~ s/\"//g;

   if($gass_from !~ /^\s*\//) #if not absolute path
   {
      $gass_from="/$gass_from";
   }
   system('globus-rcp','-b',"$hostname:$gass_from","file:$local") == 0
      or croak "globusrun failed";
}

sub stageback_local($$$$)
{
   my $self = shift;
   my $hostname = shift;
   my $cp_from = shift;
   my $local = shift;
   my $user = $self->{"username"};
   my $base_dir = $self->{"hostdb"}->{$hostname}->directory();
   my $test_dir = $self->{"directory"};


   # should I check for $cp_from.$arch????

   if($base_dir)
   {
      $cp_from="$base_dir/$cp_from";
   }
   else
   {
      if($test_dir)
      {
	 $cp_from="$test_dir/$cp_from";
      }
      else
      {
	 $cp_from="$cp_from";
      }
   }

   system('cp',$cp_from,$local) == 0
      or croak "cp failed";

}
=pod

=head2 sub startup($executable, $args)

This function starts a remote job using the specified method of
execution. It is assumed that no user interaction is required and that
the executable used (rsh, ssh, globusrun) is in the path. If the
capability perl is specified, then the job is started by invoking perl
on the executable. If gram is used for execution and the capability
mpi is specified, the jobtype is set to mpi.

B<Arguments:>

=over 8

=item * I<executable>

The executable program to be run. This should be a fully-qualified path
name.

=item * I<args>

The arguments to the executable.

=back

=cut

sub startup($$$)
{
   my $self = shift;
   my $execution;
   my @result;
   my $executable = shift;
   my $args = shift;
   my $method;

   @result = $self->{"hostdb"}->querydb($self);
   @result || croak "Could not find any hosts that met requirements";
   
   $execution = ($self->{"execution"})->[0];

   
   $method = "startup_$execution";

   print "Starting on $result[0]\n";

   $self->$method($result[0], $executable, $args);
   
   return;
}

sub startup_ssh($$$$)
{
   my $self = shift;
   my $hostname = shift;
   my $user = $self->{"username"};
   my $perl = $self->{"hostdb"}->{$hostname}->perl();
   my $base_dir = $self->{"hostdb"}->{$hostname}->directory();
   my $executable = shift;
   my $args = shift;
   my $ssh_arg;
   my $command = "";
   my $date = `date`;
   my $pid;

   chomp($date);
   $date =~ s/\s/_/g;
   $date =~ s/:/_/g;

   foreach (@{$self->{"capabilities"}})
   {
      $_ eq 'perl' && do{$args="$executable $args";
			 $executable=$perl;};
   }
   
   $args =~ s/\s*$//;

   $ssh_arg="${user}\@${hostname}";

   open(STARTUP_SCRIPT,">startup_$date") ||
       croak "Could not open startup_$date";
   print STARTUP_SCRIPT "COMM_SERVER_HOST=$self->{env}->{COMM_SERVER_HOST}\n";
   print STARTUP_SCRIPT "export COMM_SERVER_HOST\n";
   print STARTUP_SCRIPT "COMM_SERVER_PORT=$self->{env}->{COMM_SERVER_PORT}\n";
   print STARTUP_SCRIPT "export COMM_SERVER_PORT\n";
   print STARTUP_SCRIPT "PERL=$perl\n";
   print STARTUP_SCRIPT "export PERL\n";
   print STARTUP_SCRIPT "BASE_DIR=$base_dir\n";
   print STARTUP_SCRIPT "export BASE_DIR\n";
   print STARTUP_SCRIPT "CLIENT_ID=$self->{env}->{CLIENT_ID}\n";
   print STARTUP_SCRIPT "export CLIENT_ID\n";
   print STARTUP_SCRIPT "$executable $args >/dev/null 2>&1\n";
   print STARTUP_SCRIPT "rm startup_$date\n";
   close(STARTUP_SCRIPT);

   $self->stage("startup_$date");

   unlink("startup_$date");
   
   $command .= "cd $base_dir;";
   $command .= "cd $self->{directory};";
   $command .= "/bin/sh startup_$date;";
   
   defined($pid = fork) || croak "Unable to fork in startup_ssh: $!";

   if(!$pid)
   {
       system('ssh','-q',$ssh_arg,$command)  
	   and croak "SSH failed";
       exit(0);
   }

   return;
}


sub startup_gram($$$$)
{
  my $self = shift;
  my $hostname = shift;
  my $jobmanager = ($self->{"jobmanagers"})->[0];
  my $user = $self->{"username"};
  my $executable = shift;
  my $args = shift;
  my $perl = $self->{"hostdb"}->{$hostname}->perl();
  my $contact = ($self->{"hostdb"}->{$hostname}->$jobmanager())->contact();
  my $base_dir = $self->{"hostdb"}->{$hostname}->directory();
  my $directory = "${base_dir}/$self->{directory}";
  my $jobtype = "single";
  my $value;
  my $rsl;

  # It should not be necessary to fork here
  # Do not understand why I have to do this

  foreach (@{$self->{"capabilities"}})
  {
     $_ eq 'mpi' && do { $jobtype='mpi';};
     $_ eq 'perl' && do{ $args="$executable $args";
			 $executable=$perl;};
  }

  $rsl="&(executable=$executable)(arguments=$args)(environment=(COMM_SERVER_HOST \"$self->{env}->{COMM_SERVER_HOST}\")(COMM_SERVER_PORT $self->{env}->{COMM_SERVER_PORT})(PERL \"$perl\")(CLIENT_ID $self->{env}->{CLIENT_ID})(BASE_DIR \"$base_dir\"))(jobtype=\"$jobtype\")(directory=\"$directory\")";

  foreach (keys(%{$self->{"hostdb"}->{$hostname}->$jobmanager()}))
  {
     $value = ($self->{"hostdb"}->{$hostname}->$jobmanager())->$_();
     $rsl .= "($_=$value)" unless $_ eq "contact";
  }

  $contact=$hostname unless($contact);
  $contact =~ s/\"//g;

#  print "$rsl\n";
#  print "$contact\n";

  # assume that globus is in path

  system('globusrun',"-q","-b","-r",$contact,$rsl) == 0
     or croak "globusrun failed";

#  print "globusrun -q -b -r $contact $rsl\n";

#  STDOUT->flush();

  return;
}


sub startup_rsh($$$$)
{
   my $self = shift;
   my $hostname = shift;
   my $user = $self->{"username"};
   my $perl = $self->{"hostdb"}->{$hostname}->perl();
   my $executable = shift;
   my $args = shift;
   my $rsh_arg;

   foreach (@{$self->{"capabilities"}})
   {
      $_ eq 'perl' && do{$args="$executable $args";
			 $executable=$perl;};
   }
   
   $args =~ s/\s*$//;

   $rsh_arg="-l ${user} ${hostname}";

   $|=1;
   open(REMOTE_IN,"|rsh $rsh_arg > /dev/null 2>&1") 
      or croak "RSH failed";
   REMOTE_IN->autoflush();
   print REMOTE_IN "set echo\n";
   print REMOTE_IN "cd $self->{directory}\n";
   print REMOTE_IN "/bin/sh <<EOF\n";
   print REMOTE_IN "echo \$0\n";
   print REMOTE_IN "COMM_SERVER_HOST=$self->{env}->{COMM_SERVER_HOST}\n";
   print REMOTE_IN "export COMM_SERVER_HOST\n";
   print REMOTE_IN "COMM_SERVER_PORT=$self->{env}->{COMM_SERVER_PORT}\n";
   print REMOTE_IN "export COMM_SERVER_PORT\n";
   print REMOTE_IN "PERL=$perl\n";
   print REMOTE_IN "export PERL\n";
   print REMOTE_IN "CLIENT_ID=$self->{env}->{CLIENT_ID}\n";
   print REMOTE_IN "export CLIENT_ID\n";
   print REMOTE_IN "nohup $executable $args >/dev/null 2>&1 &\n";
   print REMOTE_IN "EOF\n";
   close(REMOTE_IN);
   return;
}

sub startup_local($$$$)
{
   my $self = shift;
   my $hostname = shift;
   my $user = $self->{"username"};
   my $perl = $self->{"hostdb"}->{$hostname}->perl();
   my $base_dir = $self->{"hostdb"}->{$hostname}->directory();
   my $executable = shift;
   my $args = shift;
   my $command = "";
   my $pid;

   foreach (@{$self->{"capabilities"}})
   {
      $_ eq 'perl' && do{$args="$executable $args";
			 $executable=$perl;};
   }
   
   $args =~ s/\s*$//;

   defined($pid = fork) || croak "Unable to fork in startup_ssh: $!";

   if(!$pid)
   {
       $ENV{COMM_SERVER_HOST} = $self->{env}->{COMM_SERVER_HOST};
       $ENV{COMM_SERVER_PORT} = $self->{env}->{COMM_SERVER_PORT};
       $ENV{PERL} = $perl;
       $ENV{BASE_DIR} = $base_dir;
       $ENV{CLIENT_ID} = $self->{env}->{CLIENT_ID};
       chdir($base_dir);
       chdir($self->{directory});

       system("$executable $args 2>&1") and croak "command failed";

       exit(0);
   }

   return;
}
=pod

=head1 SEE ALSO

L<Globus::Testing::HostDB|Globus::Testing::HostDB>,
L<Globus::Testing::Comm|Globus::Testing::Comm>

=cut

1;
