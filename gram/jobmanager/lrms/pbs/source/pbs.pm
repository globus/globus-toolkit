# Copyright 1999-2006 University of Chicago
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

use Globus::GRAM::Error;
use Globus::GRAM::JobState;
use Globus::GRAM::JobManager;
use Globus::Core::Paths;
use Globus::Core::Config;

# NOTE: This package name must match the name of the .pm file!!
package Globus::GRAM::JobManager::pbs;

@ISA = qw(Globus::GRAM::JobManager);

my ($mpirun, $mpiexec, $qsub, $qstat, $qdel, $cluster, $cpu_per_node, $remote_shell);

BEGIN
{
    my $config = new Globus::Core::Config(
            '${sysconfdir}/globus/globus-pbs.conf');

    $mpiexec = $config->get_attribute('mpiexec') || 'no';
    if ($mpiexec ne 'no' && ! -x $mpiexec)
    {
        $mpiexec = 'no';
    }
    $mpirun = $config->get_attribute('mpirun') || 'no';
    if ($mpirun ne 'no' && ! -x $mpirun)
    {
        $mpirun = 'no';
    }
    $qsub = $config->get_attribute('qsub') || 'no';
    $qstat = $config->get_attribute('qstat') || 'no';
    $qdel = $config->get_attribute('qdel') || 'no';
    $cluster = $config->get_attribute('cluster') || undef;
    if ($cluster eq 'no')
    {
        $cluster = undef;
    }
    my $pbs_default = $config->get_attribute('pbs_default') || '';
    if ($pbs_default ne '')
    {
        $ENV{PBS_DEFAULT} = $pbs_default;
    }

    $cpu_per_node = $config->get_attribute('cpu_per_node') || 1;
    $remote_shell = $config->get_attribute('remote_shell') || undef;
    $softenv_dir = $config->get_attribute('softenv_dir') || '';
}

sub myceil ($)
{
    my $x = shift;
    ( abs($x-int($x)) < 1E-12 ) ? int($x) : int($x < 0 ? $x : $x+1.0);
}

sub submit
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $status;
    my $pbs_job_script;
    my $pbs_job_script_name;
    my $pbs_qsub_err_name ;
    my $errfile = '';
    my $job_id;
    my $rsh_env;
    my @arguments;
    my $email_when = '';
    my $args;
    my $cache_pgm = "$Globus::Core::Paths::bindir/globus-gass-cache";
    my $soft_msc = "$softenv_dir/bin/soft-msc";
    my $softenv_load = "$softenv_dir/etc/softenv-load.sh";


    $self->log("Entering pbs submit");

    # Reject jobs that want streaming, if so configured
    if ( $description->streamingrequested() &&
	 $description->streamingdisabled() ) {

	$self->log("Streaming is not allowed.");
	return Globus::GRAM::Error::OPENING_STDOUT;
    }

    # check jobtype
    if(defined($description->jobtype()))
    {
        if($description->jobtype !~ /^(mpi|single|multiple)$/)
        {
            return Globus::GRAM::Error::JOBTYPE_NOT_SUPPORTED;
        }
    }
    if( $description->directory eq '')
    {
        return Globus::GRAM::Error::RSL_DIRECTORY();
    }
    if ($description->directory() =~ m|^[^/]|) {
        $description->add("directory",
                $ENV{HOME} . '/' . $description->directory());
    }
    chdir $description->directory() or
        return Globus::GRAM::Error::BAD_DIRECTORY();

    $self->nfssync( $description->executable() )
        unless $description->executable() eq '';
    $self->nfssync( $description->stdin() )
        unless $description->stdin() eq '';
    if( $description->executable eq '')
    {
        return Globus::GRAM::Error::RSL_EXECUTABLE();
    }
    elsif(! -f $description->executable())
    {
        return Globus::GRAM::Error::EXECUTABLE_NOT_FOUND();
    }
    elsif(! -x $description->executable())
    {
        return Globus::GRAM::Error::EXECUTABLE_PERMISSIONS();
    }
    elsif( $description->stdin() eq '')
    {
        return Globus::GRAM::Error::RSL_STDIN;
    }
    elsif(! -r $description->stdin())
    {
       return Globus::GRAM::Error::STDIN_NOT_FOUND();
    }

    $self->log("Determining job max time cpu from job description");
    if(defined($description->max_cpu_time())) 
    {
        $cpu_time = $description->max_cpu_time();
        $self->log("   using maxcputime of $cpu_time");
    }
    elsif(! $cluster && defined($description->max_time()))
    {
        $cpu_time = $description->max_time();
        $self->log("   using maxtime of $cpu_time");
    }
    else
    {
        $cpu_time = 0;
        $self->log('   using queue default');
    }

    $self->log("Determining job max wall time limit from job description");
    if(defined($description->max_wall_time()))
    {
        $wall_time = $description->max_wall_time();
        $self->log("   using maxwalltime of $wall_time");
    }
    elsif($cluster && defined($description->max_time()))
    {
       $wall_time = $description->max_time();
       $self->log("   using maxtime of $wall_time");
    }
    else
    {
        $wall_time = 0;
        $self->log('   using queue default');
    }

    $self->log('Building job script');

    $pbs_job_script_name = $self->job_dir() . '/scheduler_pbs_job_script';

    local(*JOB);
    $rc = open( JOB, '>' . $pbs_job_script_name );

    if (!$rc)
    {
        return $self->respond_with_failure_extension(
            "open: $pbs_job_script_name: $!", 
            Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }
    $rc = print JOB<<"EOF";
#! /bin/sh
# PBS batch job script built by Globus job manager
#
#PBS -S /bin/sh
EOF
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
            "print: $pbs_job_script_name: $!", 
            Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }

    if($description->name() ne '')
    {
        $rc = print JOB '#PBS -N ', $description->name(), "\n";
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                "print: $pbs_job_script_name: $!", 
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }
    if($description->email_address() ne '')
    {
        $rc = print JOB '#PBS -M ', $description->email_address(), "\n";
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                "print: $pbs_job_script_name: $!", 
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }
    if($description->emailonabort() eq 'yes')
    {
        $email_when .= 'a';
    }
    if($description->emailonexecution() eq 'yes')
    {
        $email_when .= 'b';
    }
    if($description->emailontermination() eq 'yes')
    {
        $email_when .= 'e';
    }
    if($email_when eq '')
    {
        $email_when = 'n';
    }
    $rc = print JOB "#PBS -m $email_when\n";
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
            "print: $pbs_job_script_name: $!", 
            Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }

    if($description->queue() ne '')
    {
        $rc = print JOB '#PBS -q ', $description->queue(), "\n";
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                "print: $pbs_job_script_name: $!", 
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }
    if($description->project() ne '')
    {
        $rc = print JOB '#PBS -A ', $description->project(), "\n";
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                "print: $pbs_job_script_name: $!", 
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }

    if($cpu_time != 0)
    {
        if($description->jobtype() eq 'multiple')
        {
            if ($description->totalprocesses() > 0)
            {
                $total_cpu_time = $cpu_time * $description->totalprocesses();
            }
            else
            {
                $total_cpu_time = $cpu_time * $description->count();
            }
        }
        else
        {
            $total_cpu_time = $cpu_time;
        }
        $rc = print JOB "#PBS -l pcput=${cpu_time}:00\n"
                      . "#PBS -l cput=${total_cpu_time}:00\n";
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                "print: $pbs_job_script_name: $!", 
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }

    if($wall_time != 0)
    {
        $rc = print JOB "#PBS -l walltime=${wall_time}:00\n";
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                "print: $pbs_job_script_name: $!", 
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }

    if($description->max_memory() != 0)
    {
        if($description->jobtype() eq 'multiple')
        {
            if ($description->totalprocesses() > 0)
            {
                $max_memory = $description->max_memory()
                            * $description->totalprocesses();
            }
            else
            {
                $max_memory = $description->max_memory()
                            * $description->count();
            }
        }
        else
        {
            $max_memory = $description->max_memory();
        }
        $rc = print JOB "#PBS -l mem=${max_memory}mb\n";
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                "print: $pbs_job_script_name: $!", 
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }
    $rc = print JOB '#PBS -o ', $description->stdout(), "\n" ,
                    '#PBS -e ', $description->stderr(), "\n";
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
            "print: $pbs_job_script_name: $!", 
            Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }

    if (defined $description->nodes())
    {
        #Generated by ExtensionsHandler.pm from resourceAllocationGroup elements
        $rc = print JOB '#PBS -l nodes=', $description->nodes(), "\n";
    }
    elsif($description->host_count() != 0)
    {
        $rc = print JOB '#PBS -l nodes=', $description->host_count(), "\n";
    }
    elsif($cluster && $cpu_per_node != 0)
    {
        $rc = print JOB '#PBS -l nodes=',
        myceil($description->count() / $cpu_per_node), "\n";
    }
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
            "print: $pbs_job_script_name: $!", 
            Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }

    ### SoftEnv extension ###
    if ($softenv_dir ne '')
    {
        $rc = $self->setup_softenv(
            $self->job_dir() . '/pbs_softenv_job_script',
            $soft_msc,
            $softenv_load,
            *JOB);

        if ($rc != 0)
        {
            return $self->respond_with_failure_extension(
                    "setup_softenv: $rc",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }
    #########################

    $rsh_env = '';

    foreach my $tuple ($description->environment())
    {
        if(!ref($tuple) || scalar(@$tuple) != 2)
        {
            return Globus::GRAM::Error::RSL_ENVIRONMENT();
        }

        push(@new_env, $tuple->[0] . '="' . $tuple->[1] . '"');

        $tuple->[0] =~ s/\\/\\\\/g;
        $tuple->[0] =~ s/\$/\\\$/g;
        $tuple->[0] =~ s/"/\\\"/g; #"
        $tuple->[0] =~ s/`/\\\`/g; #`

        $tuple->[1] =~ s/\\/\\\\/g;
        $tuple->[1] =~ s/\$/\\\$/g;
        $tuple->[1] =~ s/"/\\\"/g; #"
        $tuple->[1] =~ s/`/\\\`/g; #`

        $rsh_env .= $tuple->[0] . '="' . $tuple->[1] . "\";\n"
                 .  'export ' . $tuple->[0] . ";\n";
    }

    $rc = print JOB "$rsh_env\n"
                .  "#Change to directory requested by user\n"
                . 'cd ' . $description->directory() . "\n";
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
                "print: $pbs_job_script_name: $!",
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }

    @arguments = $description->arguments();

    foreach(@arguments)
    {
        if(ref($_))
        {
            return Globus::GRAM::Error::RSL_ARGUMENTS();
        }
    }
    if($#arguments >= 0)
    {
        foreach(@arguments)
        {
            $self->log("Transforming argument \"$_\"\n");
            $_ =~ s/\\/\\\\/g;
            $_ =~ s/\$/\\\$/g;
            $_ =~ s/"/\\\"/g; #"
            $_ =~ s/`/\\\`/g; #`
            $self->log("Transformed to \"$_\"\n");

            $args .= '"' . $_ . '" ';
        }
    }
    else
    {
        $args = '';
    }

    if ($description->executable() =~ m|^[^/]|)
    {
        $description->add('executable', './' . $description->executable());
    }
    if($description->jobtype() eq 'multiple' && (($description->count()==1) || !$cluster))
    {
        my $process_count;
        if ($description->totalprocesses() > 0)
        {
            $process_count = $description->totalprocesses();
        }
        else
        {
            $process_count = $description->count();
        }

        $rc = print JOB "pids=''\n"
                      . "exit_code=0\n";
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                    "print: $pbs_job_script_name: $!",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
        for(my $i = 0; $i < $process_count; $i++)
        {
            $rc = print JOB $description->executable(), " $args <",
                $description->stdin(), "&\n", "pids=\"\$pids \$!\"\n";
            if (!$rc)
            {
                return $self->respond_with_failure_extension(
                        "print: $pbs_job_script_name: $!",
                        Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
            }
        }
        $rc = print JOB <<EOF;
            for x in \$pids; do
                wait \$x
                tmp_exit_code=\$?
                if [ \$exit_code = 0 -a \$tmp_exit_code != 0 ]; then
                    exit_code=\$tmp_exit_code
                fi
            done
            exit \$exit_code
EOF
            if (!$rc)
            {
                return $self->respond_with_failure_extension(
                        "print: $pbs_job_script_name: $!",
                        Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
            }
    }
    elsif($description->jobtype() eq 'mpi' ||
            $description->jobtype() eq 'multiple')
    {
        my $count;
        if ($description->totalprocesses() > 0)
        {
            $count = $description->totalprocesses();
        }
        else
        {
            $count = $description->count();
        }
        my $cmd_script_name ;
        my $cmd_script ;
        my $stdin = $description->stdin();

        $cmd_script_name = $self->job_dir() . '/scheduler_pbs_cmd_script';

        local(*CMD);
        if ( open( CMD, ">$cmd_script_name" ) ) 
        {
            $rc = print CMD "#!/bin/sh\n";
            if (!$rc)
            {
                return $self->respond_with_failure_extension(
                        "print: $cmd_script_name: $!",
                        Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
            }

            ### SoftEnv extension ###
            $rc = $self->setup_softenv(
                $self->job_dir() . '/pbs_softenv_cmd_script',
                $soft_msc,
                *CMD);
            if ($rc != 0)
            {
                return $self->respond_with_failure_extension(
                        "setup_softenv: $rc",
                        Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
            }
            #########################

            $rc = print CMD 'cd ', $description->directory(), "\n",
                            "$rsh_env\n", 
                            $description->executable(), " $args\n";
            if (!$rc)
            {
                return $self->respond_with_failure_extension(
                        "print: $cmd_script_name: $!",
                        Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
            }
            $rc = close(CMD);
            if (!$rc)
            {
                return $self->respond_with_failure_extension(
                        "close: $cmd_script_name: $!",
                        Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
            }
            chmod 0700, $cmd_script_name;

            $self->nfssync( $cmd_script_name );
        } 
        else 
        {
            return $self->respond_with_failure_extension(
                    "open: $cmd_script_name: $!",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }

        if ($description->jobtype() eq "mpi")
        {
            if ($mpiexec ne 'no')
            {
                my $machinefilearg = "";
                if ($cluster)
                {
                    $machinefilearg = ' -machinefile $PBS_NODEFILE';
                }
                if ($description->totalprocesses() > 0)
                {
                    $rc = print JOB "$mpiexec $machinefilearg -n "
                            . $description->totalprocesses();
                }
                else
                {
                    $rc = print JOB "$mpiexec $machinefilearg -n "
                            . $description->count();
                }
                if (!$rc)
                {
                    return $self->respond_with_failure_extension(
                            "print: $pbs_job_script_name: $!",
                            Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
                }
            }
            else
            {
                if ($description->totalprocesses() > 0)
                {
                    $rc = print JOB "$mpirun -np " . $description->totalprocesses();
                }
                else
                {
                    $rc = print JOB "$mpirun -np " . $description->count();
                }
                if (!$rc)
                {
                    return $self->respond_with_failure_extension(
                            "print: $pbs_job_script_name: $!",
                            Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
                }
                if ($cluster)
                {
                    $rc = print JOB ' -machinefile $PBS_NODEFILE';
                    if (!$rc)
                    {
                        return $self->respond_with_failure_extension(
                                "print: $pbs_job_script_name: $!",
                                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
                    }
                }
            }

            $rc = print JOB " $cmd_script_name < ".$description->stdin() . "\n";
            if (!$rc)
            {
                return $self->respond_with_failure_extension(
                        "print: $pbs_job_script_name: $!",
                        Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
            }
        }
        else
        {
            my $exit_prefix=$self->job_dir() . '/exit';

            $rc = print JOB <<"EOF";

hosts=\`cat \$PBS_NODEFILE\`;
counter=0
while test \$counter -lt $count; do
    for host in \$hosts; do
        if test \$counter -lt $count; then
            $remote_shell \$host "/bin/sh $cmd_script_name; echo \\\$? > $exit_prefix.\$counter" < $stdin &
            counter=\`expr \$counter + 1\`
        else
            break
        fi
    done
done
wait

counter=0
exit_code=0
while test \$counter -lt $count; do
    /bin/touch $exit_prefix.\$counter;

    read tmp_exit_code < $exit_prefix.\$counter
    if [ \$exit_code = 0 -a \$tmp_exit_code != 0 ]; then
        exit_code=\$tmp_exit_code
    fi
    counter=\`expr \$counter + 1\`
done

exit \$exit_code
EOF
            if (!$rc)
            {
                return $self->respond_with_failure_extension(
                        "print: $pbs_job_script_name: $!",
                        Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
            }
        }
    }
    else
    {
        $rc = print JOB $description->executable(), " $args <",
            $description->stdin(), "\n";
        if (!$rc)
        {
            return $self->respond_with_failure_extension(
                    "print: $pbs_job_script_name: $!",
                    Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
        }
    }
    $rc = close(JOB);
    if (!$rc)
    {
        return $self->respond_with_failure_extension(
                "print: $pbs_job_script_name: $!",
                Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }

    $pbs_qsub_err_name = $self->job_dir() . '/scheduler_pbs_submit_stderr';
    $errfile = "2>$pbs_qsub_err_name";

    $self->nfssync( $pbs_job_script_name );
    $self->nfssync( $pbs_qsub_err_name );
    $self->nfssync( $description->stdout, 1 );
    $self->nfssync( $description->stderr, 1 );
    $self->log("submitting job -- $qsub < $pbs_job_script_name $errfile");
    chomp($job_id = `$qsub < $pbs_job_script_name $errfile`);

    if($? == 0)
    {
        $self->log("job submission successful, setting state to PENDING");
        return {JOB_ID => $job_id,
                JOB_STATE => Globus::GRAM::JobState::PENDING };
    }
    else
    {
        local(*ERR);
        open(ERR, "<$pbs_qsub_err_name");
        local $/;
        my $stderr = <ERR>;
        close(ERR);

        $self->log("qsub returned $job_id");
        $self->log("qsub stderr $stderr");

        open(ERR, ">" . $description->stderr());
        print ERR $stderr;
        close(ERR);

        $stderr =~ s/\n/\\n/g;

        $self->respond({GT3_FAILURE_MESSAGE => $stderr });
    }

    return Globus::GRAM::Error::JOB_EXECUTION_FAILED();
}

sub poll
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $job_id = $description->jobid();
    my $state;
    my $status_line;
    my $exit_code;

    $self->log("polling job $job_id");

    # Get job id from the full qstat output.
    $_ = (grep(/job_state/, $self->pipe_out_cmd($qstat, '-f', $job_id)))[0];
    # get the exit code of the qstat command.  for info search $CHILD_ERROR
    # in perlvar documentation.
    $exit_code = $? >> 8;

    $self->log("qstat job_state line is: $_");

    # return code 153 = "Unknown Job Id".
    # verifying that the job is no longer there.
    if($exit_code == 153 || $exit_code == 35)
    {
        $self->log("qstat rc is 153 == Unknown Job ID == DONE");
        $state = Globus::GRAM::JobState::DONE;
        $self->nfssync( $description->stdout() )
            if $description->stdout() ne '';
        $self->nfssync( $description->stderr() )
            if $description->stderr() ne '';
    }
    else
    {

        # Get 3rd field (after = )
        $_ = (split(/\s+/))[3];

        if(/Q|W|T/)
        {
            $state = Globus::GRAM::JobState::PENDING;
        }
        elsif(/S|H/)
        {
            $state = Globus::GRAM::JobState::SUSPENDED
        }
        elsif(/R|E/)
        {
            $state = Globus::GRAM::JobState::ACTIVE;
        }
        elsif(/C/)
        {
            $state = Globus::GRAM::JobState::DONE;
            $self->nfssync( $description->stdout() )
                if $description->stdout() ne '';
            $self->nfssync( $description->stderr() )
                if $description->stderr() ne '';
        }
        else
        {
            # This else is reached by an unknown response from pbs.
            # It could be that PBS was temporarily unavailable, but that it
            # can recover and the submitted job is fine.
            # So, we want the JM to ignore this poll and keep the same state
            # as the previous state.  Returning an empty hash below will tell
            # the JM to ignore the respose.
            $self->log("qstat returned an unknown response.  Telling JM to ignore this poll");
            return {};
        }
    }

    return {JOB_STATE => $state};
}

sub cancel
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $job_id = $description->jobid();

    $self->log("cancel job $job_id");

    $self->fork_and_exec_cmd( $qdel, $job_id );

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
