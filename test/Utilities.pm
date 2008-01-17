package Globus::Testing::Utilities;

# ====================================================================
# Utility subroutines
#
#
# ====================================================================

#use strict;
use Carp;
use File::Find;
use Cwd;
use Config;
use FileHandle;
use POSIX "sys_wait_h";

sub new {
    my $class = shift;

    my $self = {
        debug       => $ENV{TEST_DEBUG},
        color       => $ENV{TEST_COLOR},
        starttime   => $ENV{TEST_STARTTIME},
        last_globus => $ENV{GLOBUS_PATH},
        globus      => $ENV{GLOBUS_LOCATION},
        remote      => $ENV{TEST_REMOTE},
        hostname    => `hostname`,
        username    => getpwuid($<)
    };

    bless $self, $class;
    $self->setup_env();
    return $self;
}

sub hostname {
    my $self = shift;
    if (@_) { 
        $self->{hostname} = shift; 
    }
    chomp $self->{hostname};
    return $self->{hostname};
}

sub username {
    my $self = shift;
    if (@_) { 
        $self->{username} = shift; 
    }
    return $self->{username};
}

sub globus {
    my $self = shift;
    if (@_) { 
        $self->{globus} = shift; 
        $ENV{GLOBUS_LOCATION} = $self->{globus};
        $self->setup_env();
    }
    return $self->{globus};
}

sub remote {
    my $self = shift;
    if (@_) { 
        $self->{remote} = shift; 
        $ENV{TEST_REMOTE} = $self->{remote};
    }
    return $self->{remote};
}


# --------------------------------------------------------------------
# Report on output of a command
# 
#   This is mainly used in 'test-toolkit' to report on the success or
#   failure of a test.
#
# --------------------------------------------------------------------
sub report {
    my ($self, $outcome) = @_;

    if ( $ENV{TEST_COUNTER} )
    {
        print "Test Result ($ENV{TEST_COUNTER} sec):                                                                 [";
    }
    else
    {
        print "Test Result:                                                                         [";
    }
    
    if ($outcome eq "SUCCESS") {
        system("echo -en \"\\033[1;32m\"") if $self->{'color'};
        print "SUCCESS";
        system("echo -en \"\\033[0;39m\"") if $self->{'color'};
    }
    else {
        system("echo -en \"\\033[1;31m\"") if $self->{'color'};
        print "FAILED";
        system("echo -en \"\\033[0;39m\"") if $self->{'color'};
    }

    print "]\n";
}

# --------------------------------------------------------------------
# Run a command
#
# - This function is used to run commands.  You can call it one of
#   two ways:
#
#   Example call #1:  command("/bin/date");
#   Example call #2:  command("/bin/date", $timeout);
#
#   Example output:
#
#       [ /home/gose/test ] /bin/date
#       Fri Jul 19 11:49:04 CDT 2002
#
#    The second parameter specifies a timeout value (seconds) for 
#    the command.
#
# --------------------------------------------------------------------
sub command 
{
    my $self = shift;
    my $command = shift;
    my $timeout = shift || 0;
    my $output;
    my $rc;
    my $fd;
    my $pid;

    $self->debug("command -> $command");
    $self->debug("timeout -> $timeout");
   
    $command .= " 2>&1";

    # run command
    # ------------------
    
    if ($command =~ /^cd /) 
    {
        # print command line 
        # ------------------
        system("echo -en \"\\033[0;36m\"") if $self->{'color'};
        print "[ ".cwd()." ] ";
        system("echo -en \"\\033[0;39m\"") if $self->{'color'};
        print "$command\n";

        $command =~ s/^cd //;
        $command =~ s/ 2>&1$//g;
        $command =~ s/ > \/dev\/null$//;
        chdir $command;
    }
    else 
    {
        ($pid, $fd) = $self->command_blocking($command);

        if($pid == -1)
        {
            $output = "Unable to run or find $command";
            print $output."\n";
            return ($rc, $output); 
        }

        ($rc, $output) = $self->wait_command($pid, $fd, $timeout);
    
        # remove the ending \n for when we return
        chomp $output;

        $self->debug("output -> $output");
    }

    return ($rc, $output); 
}



# --------------------------------------------------------------------
# Run a blocking command
#
# - This function is used to run blocking commands.
#
#   Example call:  ($pid, $fd) = command_blocking("in.ftpd");
#
#   If the command succeeded pid will contain the pid of the command 
#   and fd will contain a file descriptor to the output generated
#   by the command. On failure $pid will be set to -1.
#
# --------------------------------------------------------------------
sub command_blocking()
{
    my $self = shift;
    my $command = shift;
    my $output = new FileHandle;
    my $cmd_pid;

    $self->debug("command -> $command");

    # print command line 
    # ------------------
    system("echo -en \"\\033[0;36m\"") if $self->{'color'};
    print "[ ".cwd()." ] ";
    system("echo -en \"\\033[0;39m\"") if $self->{'color'};
    print "$command\n";

    # run actual command
    # ------------------

    $cmd_pid = $output->open("$command 2>&1 |");

    if(defined($cmd_pid))
    {
        select((select($output), $| = 1)[0]);
    }
    else
    {
        $cmd_pid = -1;
    }
    
    return ($cmd_pid,$output);
}

# --------------------------------------------------------------------
# Wait for a blocking command
#
# - This function is used to wait for blocking commands. It will 
#   wait at most 5 minutes before killing the process it is trying 
#   to wait on.
#
#   Example call:  ($rc, $output) = wait_command($pid,$fd);
#
#   $rc will contain the return status of process $pid and $output will 
#   contain the output generated by the command.
#
# --------------------------------------------------------------------
sub wait_command()
{
    my $self = shift;
    my ($pid, $fd, $timeout) = @_;
    my $rc = 0;
    my $counter = 0;
    my $output;

    $self->debug( "wait_command: entered" );
    $self->debug( "wait_command: timeout = $timeout" );
    $self->debug( "wait_command: pid = $pid" );

    if(!defined($timeout))
    {
        $timeout = 3600;
    }

    if($timeout == 0)
    {
        while(<$fd>)
        {
            print $_ ;
            $output .= $_ ;
        }
        $fd->close();
    }
    else
    {
        while($rc == 0)
        {
            # kill after $timeout seconds
            if($counter == $timeout)
            {
                $self->debug( "wait_command: killing pid: $pid" );
                kill(9,$pid);
                $self->debug( "wait_command: killed pid: $pid" );
                sleep(1);
                $output = "Command timed out (timeout $timeout seconds).\n";
                $self->debug( "wait_command: command timed out!" );
            }
        
            $self->debug( "wait_command: calling waitpid" );
            $rc = waitpid($pid,WNOHANG);
            
            if($rc == 0)
            {
                sleep(1);
                $self->debug( "wait_command: counter = $counter" );
                $ENV{TEST_COUNTER} = $counter++;
            }
        }
    }

    if($rc != -1)
    {
        $rc = $?;
        while(<$fd>)
        {
            print $_;
            $output .= $_;
        }
        $fd->close();
    }

    
    return ($rc,$output);
}

# --------------------------------------------------------------------
# Announce to the user
#
# - This function is for announcing the user about a new section.
#
#   Example call:  announce("Your text here");
#
#   Example output:
#
#       ----------------------------------
#       Your text here
#       ----------------------------------
#
# --------------------------------------------------------------------
sub announce {
    my $self = shift @_;
    my $selfssage = shift;
    print "\n";
    system("echo -en \"\\033[0;36m\"") if $self->{'color'};
    print("====================================\n");
    print("$selfssage\n");
    print("====================================\n");
    system("echo -en \"\\033[0;39m\"") if $self->{'color'};
}

# --------------------------------------------------------------------
# Section
#
# - This function is for telling the user about a new section.
#
#   Example call:  section("Your text here");
#
#   Example output:
#
#       Your text here
#       ----------------------
#
#    Note:  It will be in color.
#
# --------------------------------------------------------------------
sub section {
    my $self = shift @_;
    my $selfssage = shift;
    system("echo -en \"\\033[0;36m\"") if $self->{'color'};
    print("\n$selfssage\n");
    print("------------------------------------\n");
    system("echo -en \"\\033[0;39m\"") if $self->{'color'};
}

# --------------------------------------------------------------------
# Inform the user
#
# - This function is for informing the user about something.
#
#   Example call:  inform("Your text here");
#
#   Example output:
#
#       Your text here
#
#    Note:  It will be in color.
#
# --------------------------------------------------------------------
sub inform {
    my $self = shift @_;
    my $selfssage = shift;
    system("echo -en \"\\033[0;36m\"") if $self->{'color'};
    print("--> $selfssage\n");
    system("echo -en \"\\033[0;39m\"") if $self->{'color'};
}

# --------------------------------------------------------------------
# Done
# --------------------------------------------------------------------
sub done {
    my $self = shift @_;
    my $finishtime = time;
    $self->debug("starttime = $self->{'starttime'}");
    $self->debug("finishtime = $finishtime");
    my @date = split /\s+/, localtime;
    $self->announce("test-toolkit: finished $date[1].$date[2].$date[4]  $date[3]");
    my $minutes = ($finishtime - $self->{'starttime'}) / 60;
    my $seconds = ($finishtime - $self->{'starttime'}) % 60;
    $self->inform("test-toolkit: runtime: $minutes minutes $seconds seconds");
    exit(0);
}

# --------------------------------------------------------------------
# Debug
# --------------------------------------------------------------------
sub debug {
    my $self = shift @_;
    if ($self->{'debug'}) {
        my $selfssage = shift;
        system("echo -en \"\\033[0;31m\"") if $self->{'color'};
        print("  DEBUG: $selfssage \n");
        system("echo -en \"\\033[0;39m\"") if $self->{'color'};
    }
}

# --------------------------------------------------------------------
# Setup the environment
# --------------------------------------------------------------------

sub setup_env
{
    my $self = shift;
    my $globus_location = $self->{'globus'};
    my $globus_path = $self->{'last_globus'};
    my $path = $ENV{PATH};
    my $ld_library_path = $ENV{LD_LIBRARY_PATH};
    my $ld_libraryn32_path = $ENV{LD_LIBRARYN32_PATH};
    my $ld_libraryn64_path = $ENV{LD_LIBRARYN64_PATH};
    my $libpath = $ENV{LIBPATH};
    my $shlib_path = $ENV{SHLIB_PATH};
    my $sasl_path = $ENV{SASL_PATH};
    my $delim;

    if($globus_location)
    {
        if($globus_path)
        {
            $path =~ s%:$globus_path[^:]*%%g;
            $path =~ s%^$globus_path[^:]*:\{0,1\}%%;
            $ld_library_path =~ s%:$globus_path[^:]*%%g;
            $ld_library_path =~ s%^$globus_path[^:]*:\{0,1\}%%;
            $ld_libraryn32_path =~ s%:$globus_path[^:]*%%g;
            $ld_libraryn32_path =~ s%^$globus_path[^:]*:\{0,1\}%%;
            $ld_libraryn64_path =~ s%:$globus_path[^:]*%%g;
            $ld_libraryn64_path =~ s%^$globus_path[^:]*:\{0,1\}%%;
            $libpath =~ s%:$globus_path[^:]*%%g;
            $libpath =~ s%^$globus_path[^:]*:\{0,1\}%%;
            $shlib_path =~ s%:$globus_path[^:]*%%g;
            $shlib_path =~ s%^$globus_path[^:]*:\{0,1\}%%;
            $sasl_path =~ s%:$globus_path[^:]*%%g;
            $sasl_path =~ s%^$globus_path[^:]*:\{0,1\}%%;
        }

        $path =~ s%:$globus_location[^:]*%%g;
        $path =~ s%^$globus_location[^:]*:\{0,1\}%%;
        $ld_library_path =~ s%:$globus_location[^:]*%%g;
        $ld_library_path =~ s%^$globus_location[^:]*:\{0,1\}%%;
        $ld_libraryn32_path =~ s%:$globus_location[^:]*%%g;
        $ld_libraryn32_path =~ s%^$globus_location[^:]*:\{0,1\}%%;
        $ld_libraryn64_path =~ s%:$globus_location[^:]*%%g;
        $ld_libraryn64_path =~ s%^$globus_location[^:]*:\{0,1\}%%;
        $libpath =~ s%:$globus_location[^:]*%%g;
        $libpath =~ s%^$globus_location[^:]*:\{0,1\}%%;
        $shlib_path =~ s%:$globus_location[^:]*%%g;
        $shlib_path =~ s%^$globus_location[^:]*:\{0,1\}%%;
        $sasl_path =~ s%:$globus_location[^:]*%%g;
        $sasl_path =~ s%^$globus_location[^:]*:\{0,1\}%%;

        $self->{'globus_path'} = $globus_location;
        $ENV{PATH} = "$globus_location/bin:$globus_location/sbin:$path";

        if(defined($ld_library_path))
        {
            $delim = ":";
        }
 
        $ENV{LD_LIBRARY_PATH} = "$globus_location/lib$delim$ld_library_path";
        
        $delim = "";

        if(defined($ld_libraryn32_path))
        {
            $delim = ":";
        }
 
        $ENV{LD_LIBRARYN32_PATH} = 
            "$globus_location/lib$delim$ld_libraryn32_path";
        
        $delim = "";

        if(defined($ld_libraryn64_path))
        {
            $delim = ":";
        }
 
        $ENV{LD_LIBRARYN64_PATH} = 
            "$globus_location/lib$delim$ld_libraryn64_path";
        
        $delim = "";

        if(defined($libpath))
        {
            $delim = ":";
        }
 
        $ENV{LIBPATH} = "$globus_location/lib$delim$libpath";
        
        $delim = "";

        if(defined($shlib_path))
        {
            $delim = ":";
        }
 
        $ENV{SHLIB_PATH} = "$globus_location/lib$delim$shlib_path";
        
        $delim = "";

        if(defined($sasl_path))
        {
            $delim = ":";
        }
 
        $ENV{SASL_PATH} = "$globus_location/lib$delim$sasl_path";
        
        $delim = "";
    }
}

sub testcred_env
{
    if (exists($_[0]) && $_[0])
    {
        $ENV{X509_CERT_DIR} = "$ENV{GLOBUS_LOCATION}/test/globus_test";
        $ENV{X509_USER_CERT} = "$ENV{X509_CERT_DIR}/usercert.pem";
        $ENV{X509_USER_KEY} = "$ENV{X509_CERT_DIR}/userkey.pem";
        $ENV{X509_USER_PROXY}="$ENV{X509_CERT_DIR}/testcred.pem";
        $ENV{GRIDMAP} = "$ENV{X509_CERT_DIR}/grid-mapfile";
    }
    else
    {
        $ENV{X509_CERT_DIR} = "$ENV{GLOBUS_LOCATION}/test/globus_test";
        $ENV{X509_USER_CERT} = "$ENV{X509_CERT_DIR}/testcred.pem";
        $ENV{X509_USER_KEY} = "$ENV{X509_CERT_DIR}/testcred.pem";
        $ENV{X509_USER_PROXY}="$ENV{X509_CERT_DIR}/testcred.pem";
        $ENV{GRIDMAP} = "$ENV{X509_CERT_DIR}/grid-mapfile";
    }
    $ENV{SECURITY_DESCRIPTOR} = "$ENV{X509_CERT_DIR}/global_security_descriptor.xml";

    return 0;
}

sub testcred_setup
{
    testcred_env(@_);

    system(". $ENV{GLOBUS_LOCATION}/test/globus_test/testcred-setup.sh");

    return $? == 0;
}

1;
