# Marko Krznaric
# London eScience Centre
# June 2003 
#
# Contributions by David McBride
# London eScience Centre
# Oct 2003
#
# Contributions by Jeff Porter
# Lawrence Berkeley National Laboratory
# Sept 2007
# 
# 

use Globus::GRAM::Error;
use Globus::GRAM::JobState;
use Globus::GRAM::JobManager;
use Globus::Core::Paths;
use Globus::Core::Config;

use IO::File;
use IPC::Open3;
use Config;

use strict;
use warnings;

package Globus::GRAM::JobManager::sge;

our @ISA = qw(Globus::GRAM::JobManager);


my ($qsub, $qstat, $qdel, $qconf,
    $mpirun, $sun_mprun,
    $default_pe, $validate_pes, $available_pes,
    $default_queue, $validate_queues, $available_queues,
    $supported_job_types, $SGE_ROOT, $SGE_CELL);

BEGIN
{
    my $config = new Globus::Core::Config('${sysconfdir}/globus/globus-sge.conf');
    my $sge_config_name;
    my $sge_config;

    $qsub = $config->get_attribute('qsub') || 'no';
    $qstat = $config->get_attribute('qstat') || 'no';
    $qdel = $config->get_attribute('qdel') || 'no';
    $qconf = $config->get_attribute('qconf') || 'no';
    $mpirun = $config->get_attribute('mpirun') || 'no';
    $sun_mprun = $config->get_attribute('sun_mprun') || 'no';

    $default_pe = $config->get_attribute('default_pe') || '';
    $validate_pes = $config->get_attribute('validate_pes') || 'no';
    $available_pes = $config->get_attribute('available_pes') || '';

    $default_queue = $config->get_attribute('default_queue') || '';
    $validate_queues = $config->get_attribute('validate_queues') || 'no';
    $available_queues = $config->get_attribute('available_queues') || '';

    if(($mpirun eq "no") && ($sun_mprun eq "no")) {
        $supported_job_types = "(single|multiple)";
    } else {
        $supported_job_types = "(mpi|single|multiple)";
    }

    $SGE_ROOT = $config->get_attribute("sge_root") || "undefined";
    $SGE_CELL = $config->get_attribute("sge_cell") || "undefined";

    $sge_config_name = $config->get_attribute('sge_config') || '';


    if ($SGE_ROOT eq 'undefined')
    {
        if (defined($sge_config_name))
        {
            open($sge_config, ". $sge_config_name && echo \$SGE_ROOT|");

            chomp($SGE_ROOT = <$sge_config>);
            close($sge_config);
        }

        if (($SGE_ROOT eq 'undefined' || $SGE_ROOT eq '')
            && exists($ENV{SGE_ROOT}))
        {
            $SGE_ROOT=$ENV{SGE_ROOT};
        }
    }
    $ENV{SGE_ROOT} = $SGE_ROOT;

    if ($SGE_CELL eq 'undefined')
    {
        if (defined($sge_config_name))
        {
            open($sge_config, ". $sge_config_name && echo \$SGE_CELL|");

            chomp($SGE_CELL = <$sge_config>);
            close($sge_config);
        }

        if (($SGE_CELL eq 'undefined' | $SGE_CELL eq '') 
            && exists($ENV{SGE_CELL}))
        {
            $SGE_CELL=$ENV{SGE_CELL};
        }
    }

    $ENV{SGE_CELL} = $SGE_CELL;
    if (-x $qconf && $available_pes eq '')
    {
        chomp($available_pes = `$qconf -spl`);
    }

    if (-x $qconf && $available_queues eq '')
    {
        chomp($available_queues = `$qconf -sql`);
    }

    if ($available_pes ne '')
    {
        $available_pes = "(" . join("|", split(/\s+/, $available_pes)) . ")";
    }
    if ($available_queues ne '')
    {
        $available_queues = "(" . join("|", split(/\s+/, $available_queues)) . ")";
    }
}


#########################################################################
#
# SUBMIT
#
########################################################################
sub submit
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $sge_job_script;
    my $sge_job_script_name;
    my $errfile = "";
    my $queue;
    my $executable;
    my $directory;
    my $stdin;
    my $job_id;
    my @arguments = ();
    my $email_when = "";
    my @environment; 
    my $qsub_err_file;
    my $args;
    my @new_env;
    my $chos;
    my $max_memory;
    my $cpu_h;
    my $cpu_m;
    my $cpu_time;
    my $wall_time;
    my $wall_h;
    my $wall_m;
    my $rc;
    my $pid;
    my ($qsub_outmsg, $qsub_errmsg);
    my ($qsub_in, $qsub_out, $qsub_err);
    my $status;
    my $mpi_pe;

    $self->log("Entering SGE submit");

    if (! -x $qsub)
    {
        $self->log("SGE qsub not available: (tried $qsub)");
        return $self->respond_with_failure_extension(
                "qsub not found in $qsub. Check $Globus::Core::Paths::sysconfdir/globus/globus-sge.conf",
                Globus::GRAM::Error::GATEKEEPER_MISCONFIGURED());
    }
    #####
    # check jobtype
    #
    if(defined($description->jobtype()))
    {
        if($description->jobtype !~ /^$supported_job_types$/)
        {
            return Globus::GRAM::Error::JOBTYPE_NOT_SUPPORTED;
        }
    }

    #####
    # check directory
    #
    $directory = $description->directory();
    if ( $directory eq '')
    {
	return Globus::GRAM::Error::RSL_DIRECTORY();
    }
    if ( $directory !~ m|^/| )
    {
        $directory = $ENV{HOME} . '/' . $directory;
    }
    if ( ! -d $directory)
    {
	return Globus::GRAM::Error::BAD_DIRECTORY();
    }

    #####
    # check executable
    #
    $executable = $description->executable();

    if( $executable eq '')
    {
	return Globus::GRAM::Error::RSL_EXECUTABLE();
    }
    if ($executable !~ m|^/|)
    {
        $executable = $directory . '/' . $executable;
    }

    if (! -e $description->executable())
    {
        return Globus::GRAM::Error::EXECUTABLE_NOT_FOUND();
    }
    elsif (! -x $description->executable())
    {
        return Globus::GRAM::Error::EXECUTABLE_PERMISSIONS();
    }
    #####
    # check stdin
    $stdin = $description->stdin();

    if( $stdin eq '')
    {
	return Globus::GRAM::Error::RSL_STDIN;
    }

    if ($stdin !~ m|^/|)
    {
        $stdin = $directory . '/' . $stdin;
    }
    if(! -r $stdin)
    {
	return Globus::GRAM::Error::STDIN_NOT_FOUND();
    }

    #####
    # RSL attributes max_cpu_time/max_wall_time (given in minutes)
    # explicitly set the maximum cpu/wall time. max_time can be used
    # for both, max_cpu_time and max_wall_time

    #####
    # determining max_wall_time
    #
    $self->log("Determining job WALL time");
    if(defined($description->max_wall_time()))
    {
	$wall_time = $description->max_wall_time();
        $self->log("  using max_wall_time of $wall_time minutes");
    }
    elsif(defined($description->max_time()))
    {
        $wall_time = $description->max_time();
        $self->log("  using max_wall_time of $wall_time minutes");
    }
    else
    {
	$wall_time = 0;
        $self->log("  using queue default");
    }
    if( ($ENV{LOGNAME} eq "ginuser") && (($wall_time>15)||($wall_time==0)) ) {
        $wall_time = 15;     # GIN User restriction                 GKJ
    }

    #####
    # determining max_cpu_time
    #
    $self->log("Determining job CPU time");
    if(defined($description->max_cpu_time()))
    {
        $cpu_time = $description->max_cpu_time();
        $self->log("  using max_cpu_time of $cpu_time minutes");
    }
    elsif(defined($description->max_time()))
    {
        $cpu_time = $description->max_time();
        $self->log("  using max_cpu_time of $cpu_time minutes");
    }
    else
    {
        $cpu_time = 0;
        $self->log("  using queue default");
    }


    #####
    # start building job script
    #
    $self->log('Building job script');

    #####
    # open script file
    #
    # rjp 2008:  there were several variants of naming the script file, some using the $tag with the cache_pgm lookup 
    #            - i suppose originating in GT3 implementation...
    #            But problems existed.  Now going to the GT4 standard seems to work for both GT2 & GT4
    #            But must check more thuroughly...
    #
    $sge_job_script_name = $self->job_dir() . '/scheduler_sge_job_script';
    $self->log("  script location: $sge_job_script_name");

    $rc = $sge_job_script = new IO::File($sge_job_script_name, '>');
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
                "open: $sge_job_script_name: $!",
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }


    #####
    # Writing script header
    #
    $rc = $sge_job_script->print("#!/bin/bash\n");
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
                "print: $sge_job_script_name: $!",
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }
    $rc = $sge_job_script->print("# Grid Engine batch job script built by ");
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
                "print: $sge_job_script_name: $!",
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }
    $rc = $sge_job_script->print("Globus job manager\n");
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
                "print: $sge_job_script_name: $!",
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }
    $rc = $sge_job_script->print("\n");
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
                "print: $sge_job_script_name: $!",
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }
    $rc = $sge_job_script->print("#\$ -S /bin/bash\n");
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
                "print: $sge_job_script_name: $!",
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }


    #####
    # Whom to send email and when
    #
    if($description->email_address())
    {
        $self->log("Monitoring job by email");
        $self->log("  email address: " . $description->email_address());
        $rc = $sge_job_script->print("#\$ -M ". $description->email_address() ."\n");
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                    "print: $sge_job_script_name: $!",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }
    if($description->emailonabort() eq 'yes')
    {
        $email_when .= 'a';
        $self->log("  email when job is aborted");
    }
    if($description->emailonexecution() eq 'yes')
    {
        $email_when .= 'b';
        $self->log("  email at the beginning of the job");
    }
    if($description->emailontermination() eq 'yes')
    {
        $email_when .= 'e';
        $self->log("  email at the end of the job");
    }
    if($description->emailonsuspend() eq 'yes')
    {
        $email_when .= 's';
        $self->log("  email when job is suspended");
    }
    if($email_when eq '')
    {
	$email_when = 'n';
        $self->log("  email(s) will not be sent");
    }
    $rc = $sge_job_script->print("#\$ -m $email_when\n");
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
                "print: $sge_job_script_name: $!",
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }


    #####
    # Defines a list of queues used to execute this job
    #
    $queue = $description->queue() || '';

    if ($queue ne '' && $validate_queues eq 'yes' && $available_queues ne '')
    {
        if ($queue !~ /^$available_queues$/)
        {
            return $self->respond_with_failure_extension(
                    "the provided RSL 'queue' parameter ($queue) is invalid. Supported queues are $available_queues",
                    Globus::GRAM::Error::INVALID_QUEUE());
        }
    }
    $queue = $description->queue() || '';

    if ($queue eq '' && $default_queue ne '')
    {
        $queue = $default_queue;
    }

    if($queue ne '')
    {
        $self->log("Using the following queue: $queue");
        $rc = $sge_job_script->print("#\$ -q " . $queue . "\n");
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                    "print: $sge_job_script_name: $!",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }


    #####
    # Writing project info.
    # (Note: as we're only supporting SGE6+ with GT4, we can do this 
    # unconditionally.  Before, we had to check to see whether we were running 
    # on SGEEE.
    #
    $self->log("Checking project details");
    if(defined($description->project()))
    {
        $self->log("  Job assigned to " . $description->project());
        $rc = $sge_job_script->print("#\$ -P ". $description->project() ."\n");
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                    "print: $sge_job_script_name: $!",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    } 
    else
    {
        $self->log("  Project not specified");
    }


    #####
    # wall_time was in minutes. Converting to SGE time format (h:m:s)
    #
    if($wall_time != 0)
    {
        $wall_m = $wall_time % 60;
        $wall_h = ( $wall_time - $wall_m ) / 60;

        $self->log("Using max WALL time (h:m:s) of $wall_h:$wall_m:00");
        $rc = $sge_job_script->print("#\$ -l h_rt=$wall_h:$wall_m:00\n");
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                    "print: $sge_job_script_name: $!",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }

    #####
    # cpu_time was in minutes. Converting to SGE time format (h:m:s)
    #
    if($cpu_time != 0)
    {
        $cpu_m = $cpu_time % 60;
        $cpu_h = ( $cpu_time - $cpu_m ) / 60;

        $self->log("Using max CPU time (h:m:s) of $cpu_h:$cpu_m:00");
        $rc = $sge_job_script->print("#\$ -l h_cpu=$cpu_h:$cpu_m:00\n");
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                    "print: $sge_job_script_name: $!",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }


    #####
    # RSL attribute for max_memory is given in Mb
    #
    $max_memory = $description->max_memory();
    if($max_memory != 0)
    {
        $self->log("Total max memory flag is set to $max_memory Mb");
        $rc = $sge_job_script->print("#\$ -l h_data=$max_memory" . "M\n");
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                    "print: $sge_job_script_name: $!",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }


    #####
    # Where to write output and error?
    #
    if(($description->jobtype() eq "single") && ($description->count() > 1))
    {
      #####
      # It's a single job and we use job arrays
      #
      if ($description->stdout() ne '/dev/null')
      {
          my $stdout = $description->stdout();

          if ($stdout !~ m|^/|)
          {
              $stdout = $description->directory() . "/$stdout";
          }

          $rc = $sge_job_script->print("#\$ -o $stdout.\$TASK_ID\n");
          if (!$rc)
          {
              return $self->respond_with_failure_extension(
                      "print: $sge_job_script_name: $!",
                      Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
          }
      }
      else
      {
          $rc = $sge_job_script->print("#\$ -o /dev/null\n");
          if (!$rc)
          {
              return $self->respond_with_failure_extension(
                      "print: $sge_job_script_name: $!",
                      Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
          }
      }

      if ($description->stderr() ne '/dev/null')
      {
          my $stderr = $description->stderr();

          if ($stderr !~ m|^/|)
          {
              $stderr = $description->directory() . "/$stderr";
          }
          $rc = $sge_job_script->print("#\$ -e $stderr.\$TASK_ID\n");
          if (!$rc)
          {
              return $self->respond_with_failure_extension(
                      "print: $sge_job_script_name: $!",
                      Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
          }
      }
      else
      {
          $rc = $sge_job_script->print("#\$ -e /dev/null\n");
          if (!$rc)
          {
              return $self->respond_with_failure_extension(
                      "print: $sge_job_script_name: $!",
                      Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
          }
      }
    }
    else
    {
        my $stdout = $description->stdout();
        my $stderr = $description->stderr();

        if ($stdout !~ m|^/|)
        {
            $stdout = $description->directory() . "/$stdout";
        }
        if ($stderr !~ m|^/|)
        {
            $stderr = $description->directory() . "/$stderr";
        }
        $rc = $sge_job_script->print(
                "#\$ -o $stdout\n" .
                "#\$ -e $stderr\n");
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                      "print: $sge_job_script_name: $!",
                      Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }


    #####
    # Constructing the environment variable
    #

    @environment = $description->environment();

    ##### OSG-Specific modification                 #####
    ##### These should not affect any non-OSG site, #####
    ##### unless you define $OSG_GRID               #####

    # First, we figure out if this is an OSG installation, and if so, where 
    # OSG is installed on the worker nodes
    my $osg_grid = '';
    my $use_osg_grid = 1;
    my $use_dynamic_wn_tmp = 1;
    map {
        if ((!ref($_)) || scalar(@$_) != 2)
        {
            return Globus::GRAM::Error::RSL_ENVIRONMENT();
        }
        if ($_->[0] eq "OSG_GRID") {
            $osg_grid =  $_->[1]; 
        } elsif ($_->[0] eq "OSG_DONT_USE_OSG_GRID_FOR_GL") {
            $use_osg_grid = 0;
        }
    } @environment;

    # If this is an OSG installation, we set GLOBUS_LOCATION based on OSG_GRID.
    if ($osg_grid ne '') {
        map {
            if ($use_osg_grid && $_->[0] eq "GLOBUS_LOCATION") { 
                $_->[1] = $osg_grid . "/globus"; 
            }
        } @environment;
    }
    ##### End OSG-Specific modification             #####


    foreach my $tuple ($description->environment())
    {
        if(!ref($tuple) || scalar(@$tuple) != 2)
        {
            return Globus::GRAM::Error::RSL_ENVIRONMENT();
        }

        push(@new_env, $tuple->[0] . "=" . $tuple->[1]);

        $tuple->[0] =~ s/\\/\\\\/g;
       	$tuple->[0] =~ s/\$/\\\$/g;
        $tuple->[0] =~ s/"/\\\"/g;
        $tuple->[0] =~ s/`/\\\`/g;

        $tuple->[1] =~ s/\\/\\\\/g;
        $tuple->[1] =~ s/\$/\\\$/g;
        $tuple->[1] =~ s/"/\\\"/g;
        $tuple->[1] =~ s/`/\\\`/g;####################################

        #####
        # Special treatment for GRD_PE or SGE_PE.
        # If jobType is mpi, this can conflict with the default PE.
        #   In that case, we override the default PE. Please note, that
        #   this can be overriden by RSL attribute parallel_envirnment!
        #
        if (($tuple->[0] eq "GRD_PE") || ($tuple->[0] eq "SGE_PE"))
        {
            if($description->jobtype() eq "mpi")
            {
                $mpi_pe = $tuple->[1];
            }
            else
            {
                $rc = $sge_job_script->print("#\$ -pe " . $tuple->[1] . " " .
                                       $description->count() . "\n");
                if (!$rc)
                {
                    return $self->respond_with_failure_extension(
                            "print: $sge_job_script_name: $!",
                            Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
                }
            }
        }
        else
        {
            $rc = $sge_job_script->print($tuple->[0] . '="' . $tuple->[1]
                                   . '"; export ' . $tuple->[0] . "\n");
            if (!$rc)
            {
                return $self->respond_with_failure_extension(
                        "print: $sge_job_script_name: $!",
                        Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
            }
        }

    }

    #####
    # Load SGE settings
    #
    $rc = $sge_job_script->print(". $SGE_ROOT/$SGE_CELL/common/settings.sh\n");
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
                "print: $sge_job_script_name: $!",
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }


    #####
    # 
    #
    $rc = $sge_job_script->print("# Change to directory requested by user\n" .
                           'cd ' . $directory . "\n");
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
                "print: $sge_job_script_name: $!",
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }


    #####
    # Transforing arguments
    #
    @arguments = $description->arguments();

    foreach(@arguments)
    {
        if(ref($_))
	{
            return Globus::GRAM::Error::RSL_ARGUMENTS;
	}
    }
    if($arguments[0])
    {
        foreach(@arguments)
        {
            $self->log("Transforming argument \"$_\"");
            $_ =~ s/\\/\\\\/g;
            $_ =~ s/\$/\\\$/g;
            $_ =~ s/"/\\\"/g;
            $_ =~ s/`/\\\`/g;
            $self->log("Transformed to \"$_\"");

            $args .= '"' . $_ . '" ';
        }
    }
    else
    {
        $args = '';
    }


    #####
    # Determining job request type.
    #
    $self->log("Determining job type");
    $self->log("  Job is of type " . $description->jobtype());
    if($description->jobtype() eq "mpi")
    {
        #####
        # It's MPI job
        #

        #####
        # Check if RSL attribute parallel_environment is provided
        #
        if ($description->parallel_environment())
        {
            $mpi_pe = $description->parallel_environment();
        }

       	if((!$mpi_pe || $mpi_pe eq "NONE" || $mpi_pe eq 'no')) {
            if ($default_pe eq '') {
                $self->log("ERROR: Parallel Environment (PE) failure!");
                $self->log("  MPI job was submitted, but no PE set");
                $self->log("  by neither user nor administrator");
                return $self->respond_with_failure_extension(
                        "mpi job request missing required parallel_environment attribute. Supported environments $available_pes",
                        Globus::GRAM::Error::PARAMETER_NOT_SUPPORTED());
            } else {
                $self->log("Using default PE ($default_pe)");
                $mpi_pe = $default_pe;
            }
        }
        if ($mpi_pe ne '' && $validate_pes eq 'yes' && $available_pes ne '') {
            if ($mpi_pe !~ m|^$available_pes$|) {
                return $self->respond_with_failure_extension(
                        "invalid parallel_environment attribute '$mpi_pe'. Supported values are $available_pes",
                        Globus::GRAM::Error::PARAMETER_NOT_SUPPORTED());
            }
        }
        $self->log("  PE is $mpi_pe");
        $rc = $sge_job_script->print("#\$ -pe $mpi_pe "
                               . $description->count() . "\n");
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                    "print: $sge_job_script_name: $!",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }

        if (($sun_mprun eq "no") && ($mpirun eq "no"))
        {
            return Globus::GRAM::Error::INVALID_SCRIPT_REPLY;
        }
        elsif ($sun_mprun ne "no")
        {
            #####
            # Using Sun's MPI.
            #
            $rc = $sge_job_script->print("$sun_mprun -np "
                                   .  $description->count() . " "
                                   . $executable . " $args < "
                                   . $stdin . "\n");
            if (!$rc)
            {
                return $self->respond_with_failure_extension(
                        "print: $sge_job_script_name: $!",
                        Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
            }
        }
        else
        {
            #####
            # Using non-Sun's MPI.
            #
            $rc = $sge_job_script->print("$mpirun " 
                                   . $executable . " $args < "
                                   . $stdin . "\n");
            if (!$rc)
            {
                return $self->respond_with_failure_extension(
                        "print: $sge_job_script_name: $!",
                        Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
            }
        }
    }
    elsif($description->jobtype() eq "multiple")
    {
        #####
        # It's a multiple job
        #
        $self->log("  forking multiple requests");
	$rc = $sge_job_script->print("pids=''\nexit_code=0\n");
	if (!$rc)
	{
	    return $self->respond_with_failure_extension(
		    "print: $sge_job_script_name: $!",
		    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
	}
        for(my $i = 0; $i < $description->count(); $i++)
        {
            $rc = $sge_job_script->print($executable . " $args < "
                                   . $stdin . "&\npids=\"\$pids \$!\"\n");
            if (!$rc)
            {
                return $self->respond_with_failure_extension(
                        "print: $sge_job_script_name: $!",
                        Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
            }
        }

        $rc = $sge_job_script->print("for x in \$pids; do\n"
		. "wait \$x; tmp_exit_code=\$?;\n"
		. "if [ \$exit_code = 0 -a \$tmp_exit_code != 0 ]; then\n"
		. "    exit_code=\$tmp_exit_code\n"
		. "fi\ndone\nexit \$exit_code\n");
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                    "print: $sge_job_script_name: $!",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }
    elsif($description->count() > 1)
    {
        #####
        # (single & count>1) -> Using job arrays
        #
        $self->log("  using job arrays with count " . $description->count());
        $rc = $sge_job_script->print("#\$ -t 1-" . $description->count() . "\n"
                               . $executable . " $args < "
                               . $stdin . "\n");
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                    "print: $sge_job_script_name: $!",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }
    else
    {
        #####
        # Single execution job
        #
        $rc = $sge_job_script->print($executable . " $args < "
                               . $stdin . "\n");
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                    "print: $sge_job_script_name: $!",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }

    #####
    # SGE job script is successfully built! :-)
    #
    $self->log("SGE job script successfully built! :-)");
    $rc = $sge_job_script->close();
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
                "print: $sge_job_script_name: $!",
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }

    #####
    # Submitting a job
    #
    $self->log("Submitting a job");

#
# rjp 2008 - next if block is VDT addition for 'chos' environments e.g. PDSF
#
    if ( -r "$ENV{HOME}/.chos" ){
      $chos=`cat $ENV{HOME}/.chos`;
      $chos=~s/\n.*//;
      $ENV{CHOS}=$chos;
    }

    $self->log("executing $qsub $sge_job_script_name");
    local(*QSUB_IN);
    local(*QSUB_OUT);
    local(*QSUB_ERR);
    $pid = IPC::Open3::open3(
            \*QSUB_IN, \*QSUB_OUT, \*QSUB_ERR,
            $qsub, $sge_job_script_name);
    if (!$pid)
    {
        return $self->respond_with_failure_extension(
                "print: $sge_job_script_name: $!",
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }

    $self->log("enabling slurp");
    local($/);

    $qsub_in = \*QSUB_IN;
    $qsub_out = \*QSUB_OUT;
    $qsub_err = \*QSUB_ERR;

    $qsub_outmsg = <$qsub_out>;
    $qsub_errmsg = <$qsub_err>;

    waitpid($pid, 0);
    $status = $? >> 8;

    close($qsub_in); 
    close($qsub_out);
    close($qsub_err);

    if ($qsub_outmsg)
    {
        chomp($qsub_outmsg);
        $self->log("qsub stdout: $qsub_outmsg");
    }
    else
    {
        $qsub_outmsg = '';
    }

    if ($qsub_errmsg)
    {
        chomp($qsub_errmsg);
        $self->log("qsub stderr: $qsub_errmsg");
    }
    else
    {
        $qsub_errmsg = '';
    }
    $self->log("qsub exited with $status");

    if($status == 0 && $qsub_outmsg ne '')
    {
        $self->log("  successfully submitted");

        # get job ID
        $job_id = (split(/\s+/, $qsub_outmsg))[2];

        # in the case we used job arrays
        if ($job_id =~ m/(\d+)\.(\d+)-(\d+)/)
        {
            my $task_root = $1;
            my $task_min = $2;
            my $task_max = $3;
            my $i;

            $job_id = "";

            $job_id = "$task_root.$task_min";
            for ($i = int($task_min) + 1; $i <= $task_max; $i++)
            {
                $job_id .= ",$task_root.$i"
            }
        }
        else
        {
            $job_id .= ".0";
        }
	return {JOB_ID => $job_id,
	        JOB_STATE => Globus::GRAM::JobState::PENDING };
    }
    else
    {
        $qsub_outmsg =~ s/\n/\\n/g if ($qsub_outmsg);
        $qsub_errmsg =~ s/\n/\\n/g if ($qsub_errmsg);
        if ($description->project())
        {
            $self->log("check if the project specified does exist");
        }

        return $self->respond_with_failure_extension(
                "qsub failed: $qsub_outmsg\\n$qsub_errmsg",
                Globus::GRAM::Error::INVALID_SCRIPT_REPLY);
    }

    #####
    # If we reach this - invalid script response
    #
    return Globus::GRAM::Error::INVALID_SCRIPT_REPLY;
}


#########################################################################
#
# POLL
#
########################################################################
sub poll
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $job_id = $description->job_id();
    my $state;
    my $status_line;
    my $job_out = $description->stdout();
    my $job_err = $description->stderr();

    $self->log("polling job $job_id");

    # strip off task list
    $job_id =~ s/\..*//;

    my ($tries)=0;
    my ($notexist);
    
    if (! -x $qstat)
    {
        $self->log("SGE qstat not available---configured to look in $qstat");
        return $self->respond_with_failure_extension(
                "qsub not found in $qsub. Check $Globus::Core::Paths::sysconfdir/globus/globus-sge.conf",
                Globus::GRAM::Error::GATEKEEPER_MISCONFIGURED());
    }
    POLL_AGAIN:    
       my (@output) = `$qstat -j $job_id 2>&1`;	# Query job_id by number.
 
    if ($#output == -1 ){
    	if ($tries < 2){
	   sleep(2);
	   $tries++;
	   goto POLL_AGAIN;
	} else {
	   $notexist = "error";                 # ensures that a queue failure will equate
	                                        # to job error from the Condor side
	}
    } else {
        # there is a result
        $notexist = $output[0];		        # Obtain first line of output (STDOUT or STDERR)    
    }
 
    if ($notexist =~ /do not exist/)		# Check to see if first line indicates job doesn't exist any more.
    {
      # Job no longer exists in SGE job manager.  It must have finished.
      $self->log("Job $job_id has completed.");
      $state = Globus::GRAM::JobState::DONE;

      $self->log("Writing job STDOUT and STDERR to cache files.");

      if(($description->jobtype() eq "single") && ($description->count() > 1))
      #####
      # Jobtype is single and count>1. Therefore, we used job arrays. We
      # need to merge individual output/error files into one.
      #
      {
	# [dwm] Use append, not overwrite to work around file streaming issues.
        my $fh = new IO::File(">>", $job_out);
        for my $fn (<"$job_out.*">) {
            my $in = new IO::File("<$fn");
            my $line;

            while ($line = <$in>) {
                $fh->print($line);
            }
            $in->close();
        }
        $fh->close();

        $fh = new IO::File(">>", $job_err);
        for my $fn (<"$job_err.*">) {
            my $in = new IO::File("<$fn");
            my $line;

            while ($line = <$in>) {
                $fh->print($line);
            }
            $in->close();
        }
        $fh->close();
      }
      
      $self->log("Returning job success.");
    }
    else
    {
	# SGE still knows about the job, hence it cannot have completed yet.
	# Determine its current state and notify any interested parties.

	$_ = join ' ', @output; 	# Obtain scheduler details from output, if any.
	
	# FIXME:
	# Unfortunately, the nice single-character state field isn't printed
	# if we do a lookup on a specific job with qstat, so we have to guess
	# a little more that we would like.
	# This is probably best fixed in SGE itself.

	if (/"job is in error state"/) {
	  $self->log("  Job $job_id has failed!");
	  $state = Globus::GRAM::JobState::FAILED;
	}
	elsif(/hold|suspend/) {
 	  $self->log("  Job is suspended.");
	  $state = Globus::GRAM::JobState::SUSPENDED;
	}
	# [dwm] Suggested improvement for 'running' match from Dave Robson at Jet.uk.
	elsif(/usage .*cpu=[0-9]/) {
	  $self->log("  Job is running.");
	  $state = Globus::GRAM::JobState::ACTIVE;
	}
	else { 
#
# rjp 2008:  With this 'else', after job is done but before it's removed from the queue, 
#            globus will think the job is back to pending
#
	  $self->log("  Job is still queued for execution.");
 	  $state = Globus::GRAM::JobState::PENDING;
	}
    }

    return {JOB_STATE => $state};
}



#########################################################################
#
# CANCEL
#
########################################################################
sub cancel
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $job_id = $description->jobid();

    $self->log("cancel job $job_id");

    # strip off task list
    $job_id =~ s/\..*//;

    system("$qdel $job_id >/dev/null 2>/dev/null");

    if($? == 0)
    {
      return { JOB_STATE => Globus::GRAM::JobState::FAILED }
    }

    return Globus::GRAM::Error::JOB_CANCEL_FAILED();
}

sub respond_with_failure_extension
{
    my $self = shift;
    my $msg = shift;
    my $rc = shift;

    $self->respond({GT3_FAILURE_MESSAGE => $msg });
    return $rc;
}

1;
