package Utilities;

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

    print "Test Result:                                                                        [";
    
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
#   Example call #2:  command("/bin/date", 1);
#
#   Example output:
#
#       [ /home/gose/test ] /bin/date
#       Fri Jul 19 11:49:04 CDT 2002
#
#    Passing a '1' in as the second argument will return the output.
#
# --------------------------------------------------------------------
sub command {
    my $self = shift;
    my ($command, $output, $noerror) = @_;

    $self->debug("command -> $command");
    $self->debug("return output -> $output");
    $self->debug("don't fail on error -> $noerror");
   
    $command .= " 2>&1";

    # print command line 
    # ------------------
    system("echo -en \"\\033[0;36m\"") if $self->{'color'};
    print "[ ".cwd()." ] ";
    system("echo -en \"\\033[0;39m\"") if $self->{'color'};
    print "$command\n";

    # run actual command
    # ------------------
    if ($command =~ /^cd /) {
        $command =~ s/^cd //;
        $command =~ s/ 2>&1$//;
        $command =~ s/ > \/dev\/null$//;
        chdir $command;
    }
    else {
        if ($output) {
            $output = `$command`;

            # remove the ending \n for when we return
            chomp $output;
            if ($output !~ /^$/) {
                print $output."\n";
            }
        }
        else {
            system("$command");
        }
    }

    if ( (!$noerror) and ($? != 0) ) {
        $self->inform("Your command returned non-zero!");
        $self->inform("Error: $!");
        exit(1);
    }

    if ($output) { 
        $self->debug("output -> $output");
        return $output; 
    }
    else { 
        return; 
    }
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
    my $output;
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

    $cmd_pid = open($output,"$command 2>&1 |");

     if($cmd_pid != -1)
     {
         select((select($output), $| = 1)[0]);
     }
    
    return ($cmd_pid,$output);
}

# --------------------------------------------------------------------
# Wait for a blocking command
#
# - This function is used to wait for blocking commands.
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
    my ($pid,$fd) = @_;
    my $rc;
    my $output;

    $rc = waitpid($pid,0);

    while(<$fd>)
    {
        $output .= $_;
    }
   
    close($fd);
    
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


1;
