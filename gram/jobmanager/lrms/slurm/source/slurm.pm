# Copyright (C) 2010-2011
# Author: Kurakin Roman, <rik@inse.ru>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use Globus::GRAM::Error;
use Globus::GRAM::JobState;
use Globus::GRAM::JobManager;
use Globus::Core::Paths;
use Globus::Core::Config;

use IO::File;
use IPC::Open3;
use Config;

# Require 5.8 for open file handle to string idiom for handling softenv below
use v5.8;

package Globus::GRAM::JobManager::slurm;

our @ISA = qw(Globus::GRAM::JobManager);

our (
    $mpirun,
    $ibrun,
    $sbatch,
    $srun,
    $scontrol,
    $scancel,
    $salloc,
    $supported_job_types,
    $slurm_path,
    $mpi_types,
    $openmpi_path,
    $mpich2_path,
    $soft_msc,
    $softenv_dir,
    $softenv_load);


BEGIN
{
    sub find_program($)
    {
        my $program = shift;
        foreach my $path (split(/:/, "$ENV{PATH}:/sbin:/bin:/usr/sbin:/usr/bin"))
        {
            if (-x "$path/$program")
            {
                return "$path/$program";
            }
        }
        return 'no';
    }
    my $config = new Globus::Core::Config(
            '${sysconfdir}/globus/globus-slurm.conf');

    if (! $config)
    {
        $mpirun = 'no';
        $ibrun = 'no';
        $sbatch = 'no';
        $srun = 'no';
        $scontrol = 'no';
        $scancel = 'no';
        $salloc = 'no';
        $supported_job_types = "single|multiple";
    }
    else
    {
        $mpirun = $config->get_attribute('mpirun') || 'no';
        if ($mpirun ne 'no' && ! -x $mpirun)
        {
            $mpirun = 'no';
        }
        # TACC utility for parallel jobs
        $ibrun = $config->get_attribute('ibrun') || 'no';

        if ($mpirun eq 'no' && $ibrun eq 'no')
        {
            $supported_job_types = "single|multiple";
        }
        else
        {
            $supported_job_types = "mpi|single|multiple";
        }

        $srun = $config->get_attribute('srun') || 'no';
        $sbatch = $config->get_attribute('sbatch') || 'no';
        $scancel = $config->get_attribute('scancel') || 'no';
        $scontrol = $config->get_attribute('scontrol') || 'no';
        $salloc = $config->get_attribute('salloc') || 'no';
        $slurm_path= $config->get_attribute('slurm_path') || 'no';
        $mpi_types= $config->get_attribute('mpi_types') || 'no';
        if ($mpi_types ne 'no')
        {
            chomp($mpi_types);
            $mpi_types =~ s/\s+/|/g;
        }
        $openmpi_path= $config->get_attribute('openmpi_path') || 'no';
        $mpich2_path= $config->get_attribute('mpich2_path') || 'no';
        $softenv_dir = $config->get_attribute('softenv_dir') || '';
        $soft_msc       = "$softenv_dir/bin/soft-msc";
        $softenv_load   = "$softenv_dir/etc/softenv-load.sh";
    }
    if ($srun eq 'no')
    {
        $srun = find_program('srun');
    }
    if ($sbatch eq 'no')
    {
        $sbatch = find_program('sbatch');
    }
    if ($scancel eq 'no')
    {
        $scancel = find_program('scancel');
    }
    if ($scontrol eq 'no')
    {
        $scontrol = find_program('scontrol');
    }
    if ($salloc eq 'no')
    {
        $salloc = find_program('salloc');
    }
}

sub job_description_class
{
    return 'Globus::GRAM::DefaultHandlingJobDescription';
}

sub validate_jobtype($)
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $jobtype = $description->jobtype();
    my $mpi_type = $description->mpi_type();

    if ($jobtype !~ /^$supported_job_types$/) {
        return Globus::GRAM::Error::JOBTYPE_NOT_SUPPORTED;
    }
    if ($jobtype eq 'mpi' && $mpi_type !~ /^$mpi_types$/)
    {
        return Globus::GRAM::Error::JOBTYPE_NOT_SUPPORTED;
    }
}

sub validate_executable($)
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $exe = $description->executable();
    if ($exe eq '')
    {
        return Globus::GRAM::Error::RSL_EXECUTABLE();
    }
    $self->nfssync($exe);
    if (! -e $exe)
    {
        return Globus::GRAM::Error::EXECUTABLE_NOT_FOUND();
    }
    if (! -x $exe)
    {
        return Globus::GRAM::Error::EXECUTABLE_PERMISSIONS();
    }
}

sub validate_stdin($)
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $stdin = $description->stdin();

    $self->nfssync($stdin);
    if ($stdin eq '')
    {
        return Globus::GRAM::Error::RSL_STDIN();
    }
    if (! -r $stdin)
    {
        return Globus::GRAM::Error::STDIN_NOT_FOUND();
    }

    return undef;
}

sub validate_arguments($)
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my @arguments = $description->arguments();

    foreach my $argument (@arguments) {
        if (ref($argument)) {
            return Globus::GRAM::Error::RSL_ARGUMENTS();
        }
    }
    return undef;
}

sub validate_directory($)
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my @directory = $description->directory();

    return Globus::GRAM::Error::RSL_DIRECTORY() if (!@directory);
    return Globus::GRAM::Error::RSL_DIRECTORY() if (!$directory[0]);

    if (scalar(@directory) != 1 || ref($directory[0])) {
        $self->log("return RSL_DIRECTORY");
        return Globus::GRAM::Error::RSL_DIRECTORY();
    }
    $self->log("checks out ok");
    return undef;
}

sub validate_environment($)
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my @env = $description->environment();

    foreach my $env (@env) {
        $self->log("Checking env $env");
        if (ref($env) ne 'ARRAY') {
            return Globus::GRAM::Error::RSL_ENVIRONMENT();
        } elsif (scalar(@{$env}) != 2) {
            return Globus::GRAM::Error::RSL_ENVIRONMENT();
        } elsif (ref($env->[0]) || ref($env->[1])) {
            return Globus::GRAM::Error::RSL_ENVIRONMENT();
        }
    }
    return undef;
}

sub validate($)
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $result;

    # Reject jobs that want streaming, if so configured
    if ($description->streamingrequested() &&
	$description->streamingdisabled() ) {

	$self->log("Streaming is not allowed.");
	return Globus::GRAM::Error::OPENING_STDOUT;
    }

    # validate some input parameters
    return $result if ($result = $self->validate_jobtype());
    return $result if ($result = $self->validate_executable());
    return $result if ($result = $self->validate_stdin());
    return $result if ($result = $self->validate_arguments());
    return $result if ($result = $self->validate_directory());
    return $result if ($result = $self->validate_environment());

    return undef;
}

sub format_time_value($)
{
    my $val = int(shift);
    if($val != 0)
    {
       my $m = $val % 60;
       my $h = ( $val - $m ) / 60;

       return "$h:$m:00";
    }
}

sub create_prologue($)
{
    my $self = shift;
    my $prologue = ["#!/bin/sh", "#GRAM job for SLURM"];
    my $description = $self->{JobDescription};
    my $emails = "";

    my $attr_map = [
        ['host_count', sub { "#SBATCH -N ".shift }],
        ['count', sub {
            my $count = shift;
            if ($description->host_count())
            {
                return "#SBATCH --tasks-per-node=$count";
            }
            else
            {
                return "#SBATCH -n $count";
            }
        }],
        ['name' => sub { "#SBATCH -J ".shift; }],
        ['email_address', sub { "#SBATCH --mail-user=" . shift; }],
        ['job_dependency', sub { "#SBATCH --dependency=afterany:" . shift; }],
        ['queue', sub { "#SBATCH -p ".shift }],
        ['project', sub { "#SBATCH -A ".shift; }],
        ['wall_time', sub { "#SBATCH -t " . format_time_value(shift) }],
        ['stdout', sub { return "#SBATCH -o ".shift; }],
        ['stderr', sub { "#SBATCH -e ".shift; }],
        ['module_del',  sub {
            my @module_del = @_;
            join("", map {"module del $_\n"} @module_del);
        }],
        ['module_add', sub {
            my @module_add = @_;
            return join("", map {"module add $_\n"} @module_add);
        }],
        ['max_memory', sub {
            my $max_memory = shift;
            if ($description->host_count())
            {
                "#SBATCH --mem=$max_memory";
            }
            else
            {
                "#SBATCH --mem-per-cpu=$max_memory";
            }
        }],
        ['environment', sub {
            my @environment = @_;
            my @res = map {
                $self->shell_escape($_->[0]) . "=\""
                . $self->shell_escape($_->[1]) . "\"" } @environment;
            push(@res, map {"export $_->[0]"} @environment);
            return @res;
        }],
        ['jobtype', sub {
            my $jobtype = shift;
            my $mpi_type = $description->mpi_type();
            if ($jobtype eq 'mpi') {
                if ($mpi_type eq 'openmpi' && $openmpi_path ne '') {
                    return (
                        "export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:$openmpi_path/lib",
                        "export PATH=$openmpi_path/bin");
                } elsif ($mpi_type eq 'mpich2' && $mpich2_path ne '') {
                    return (
                        "export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:$mpich2_path/lib",
                        "export PATH=$mpich2_path/bin");

                }
            }
        }]
    ];

    foreach my $mapping (@{$attr_map})
    {
        my ($attr, $subref) = @{$mapping};
        my $val = $description->get($attr);
        if ($val)
        {
            my @subres;

            if (ref($val))
            {
                @subres = $subref->(@{$val});
            }
            else
            {
                @subres = $subref->($val);
            }
            if (@subres)
            {
                push(@{$prologue}, @subres);
            }
        }
    }
    if($description->email_on_abort() eq 'yes' &&
       $description->email_on_execution() eq 'yes' &&
       $description->email_on_termination() eq 'yes')
    {
        push(@{$prologue}, "#SBATCH --mail-type=ALL");
    }
    else
    {
        if($description->email_on_abort() eq 'yes')
        {
            push(@{$prologue}, "#SBATCH --mail-type=FAIL");
        }
        if($description->email_on_execution() eq 'yes')
        {
            push(@{$prologue}, "#SBATCH --mail-type=BEGIN");
        }
        if($description->email_on_termination() eq 'yes')
        {
            push(@{$prologue}, "#SBATCH --mail-type=END");
        }
    }

    ### SoftEnv extension ###
    if ($softenv_dir ne '')
    {
        my $softenv_extension_text ='';
        my $softenv_extension_fh;
        open($softenv_extension_fh, '>', \$softenv_extension_text);

        $self->setup_softenv(
            $self->job_dir() . '/slurm_softenv_job_script',
            $soft_msc,
            $softenv_load,
            $softenv_extension_fh);
        if ($softenv_extension_text ne '' )
        {
            push(@{$prologue}, split(/\n+/, $softenv_extension_text));
        }
    }

    push (@{$prologue}, 'cd ' . $description->directory());
    return $prologue;
}

sub create_execution_statement
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $jobtype = $description->jobtype();
    my $exe = $description->executable();
    my $mpi_type = $description->mpi_type();
    my @args = $description->arguments();

    if ($jobtype eq 'multiple') {
        unshift(@args, $exe);
        $exe = $srun;
    } elsif ($jobtype eq 'mpi') {
	if ( $mpi_type eq 'openmpi') {
            unshift(@args, $exe);
            $exe = $mpirun;
        } elsif ($mpi_type eq 'mpich2') {
            unshift(@args, $mpirun);
            $exe = $srun;
        }
    }
    return join(" ", map { "\"".$self->shell_escape($_)."\"" } ($exe, @args));
}

sub create_epilogue
{
    return [];
}

sub submit
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $job_dir = $self->job_dir();
    my $status;
    my $prologue;
    my $execution_statement;
    my $epilogue;
    my $slurm_job_script;
    my $slurm_job_script_name;
    my $slurm_sbatch_err_name ;
    my $errfile = '';
    my $job_id;
    my $result;
    my $sub_res;

    $self->log("Entering slurm submit");

    $result = $self->validate();
    if ($result)
    {
        return $result;
    }

    $prologue = $self->create_prologue();
    if (ref($prologue) eq 'Globus::GRAM::Error')
    {
        return $prologue;
    }

    $execution_statement = $self->create_execution_statement();
    if (ref($execution_statement) eq 'Globus::GRAM::Error')
    {
        return $execution_statement;
    }
    $epilogue = $self->create_epilogue();
    if (ref($epilogue) eq 'Globus::GRAM::Error')
    {
        return $epilogue;
    }

    $self->log('Building job script');
    $slurm_job_script_name = "$job_dir/scheduler_slurm_job_script";

    local(*JOB);
    open( JOB, '>' . $slurm_job_script_name ) ||
           return $self->respond_with_failure_extension(
                   "print: $slurm_job_script_name: $!",
                   Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    $status = print JOB join("\n",
            @{$prologue}, $execution_statement, @{$epilogue}) . "\n";

    close(JOB);
    if (! $status )
    {
       return $self->respond_with_failure_extension(
               "print: $slurm_job_script_name: $!",
               Globus::GRAM::Error::TEMP_SCRIPT_FILE_FAILED());
    }

    $slurm_sbatch_err_name = "$job_dir/scheduler_slurm_submit_stderr";
    $errfile = "2>$slurm_sbatch_err_name";

    $self->nfssync( $slurm_job_script_name );
    $self->nfssync( $slurm_sbatch_err_name );
    $self->nfssync( $description->stdout, 1 );
    $self->nfssync( $description->stderr, 1 );
    $self->log("submitting job -- $sbatch $slurm_job_script_name $errfile");
    $sub_res = `cd $job_dir; $sbatch $slurm_job_script_name $errfile`;
    $job_id = (grep(/^Submitted batch job \d+$/, split(/\n/, $sub_res)))[0];

    if ($? == 0 && defined $job_id) {
        $job_id =~ s/^Submitted batch job (\d+)$/\1/;
        $self->log("job submission successful, setting state to PENDING");
        return {JOB_ID => $job_id,
                JOB_STATE => Globus::GRAM::JobState::PENDING };
    }

    if ($? == 0 && not defined $job_id) {
        local(*ERR);
        local $/;
        $self->log("failed to findout job id, sbatch returned $sub_res");

        open(ERR, ">" . $description->stderr());
        print ERR "Failed to findout job id, sbatch returned $sub_res\n";
        print ERR "If you are sure this is target resource failure, ";
        print ERR "please, contact\n";
        print ERR "resource administrator.\n";
        close(ERR);

        $sub_res =~ s/\n/\\n/g;
        $self->respond({GT3_FAILURE_MESSAGE => $sub_res});
    } else {
        local(*ERR);
        local $/;

        open(ERR, "<$slurm_sbatch_err_name");
        my $stderr = <ERR>;
        close(ERR);

        $self->log("sbatch returned $sub_res");
        $self->log("sbatch stderr $stderr");

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
    my $exit_code;
    my $pid;
    my ($scontrol_in, $scontrol_out, $scontrol_err);
    my $out;

    $self->log("polling job $job_id");

    # Get job state line from the scontrol command output.
    $pid = IPC::Open3::open3($scontrol_in, $scontrol_out, $scontrol_err,
        $scontrol, 'show', 'job', $job_id);
    close($scontrol_in);
    waitpid($pid, 0);

    $exit_code = $? >> 8;

    # scontrol returns 1 on any error, see comment in scontrol.c code.
    if ($exit_code == 1) {
        local $/;
        $out = (grep(/slurm_load_jobs error:/, <$scontrol_out>))[0];
        if (defined $out) {
            chomp ($out);
            # Assume the job was complited.
            if ($out =~ /slurm_load_jobs error: Invalid job id specified/) {
                $self->log("scontrol: $out");
    		return {JOB_STATE => Globus::GRAM::JobState::DONE};
            }
            # We lost connection to the slurm, tell ignore the poll by an
            # empty hash. 
            if ($out =~ /slurm_load_jobs error: Unable to contact slurm controller/) {
                $self->log("scontrol: Unable to contact slurm");
                return {};
            }
            # Unknown slurm error.  Just treat as local slurm problems, tell
            # to ignore the poll by an empty hash.
            $self->log("scontrol: unknown slurm error: $out");
            return {};
        }
        # probably non-scontrol error, just bypass it to the next section.
    }

    if ($exit_code != 0) {
        my @out = <$scontrol_err>;
        if (defined ((grep(/^open3:/, @out))[0])) {
            $self->log("slurm.pm: @out");
        } else {
            # Should return some special error in this case???
            $self->log("slurm.pm: @out");
        }
        # We are failed to find out job state, so just tell to ignore
        # the poll by an empty hash.
        return {};
    }

    $_ = (grep(/JobState/, <$scontrol_out>))[0];
    $_ =~ s/^.*JobState=(\S+)\s.*$/$1/ unless not defined;

    if (not defined or $_ eq '') {
        # We are failed to find out job state, so just tell to ignore
        # the poll by an empty hash.
        $self->log("slurm.pm: could not find job state");
        return {};
    }

    if (/PENDING|CONFIGURING/) {
        $state = Globus::GRAM::JobState::PENDING;
    } elsif (/RUNNING|COMPLETING/) {
        $state = Globus::GRAM::JobState::ACTIVE;
    } elsif (/FAILED|CANCELLED|NODE_FAIL/) {
        $state = Globus::GRAM::JobState::FAILED;
    } elsif (/COMPLETED|TIMEOUT/) {
        $state = Globus::GRAM::JobState::DONE;
        $self->nfssync( $description->stdout() )
            if $description->stdout() ne '';
        $self->nfssync( $description->stderr() )
            if $description->stderr() ne '';
    } elsif (/SUSPENDED/) {
        $state = Globus::GRAM::JobState::SUSPENDED;
    } else {
        # We got unknown job state, so just tell to ignore
        # the poll by an empty hash.
        $self->log("slurm.pm: unknown job state returned");
        return {};
    }

    return {JOB_STATE => $state};
}

sub cancel
{
    my $self = shift;
    my $description = $self->{JobDescription};
    my $job_id = $description->jobid();

    $self->log("cancel job $job_id");

    $self->fork_and_exec_cmd($scancel, "--signal=KILL", $job_id);

    if ($? == 0) {
        return { JOB_STATE => Globus::GRAM::JobState::FAILED }
    }

    return Globus::GRAM::Error::JOB_CANCEL_FAILED();
}

1;
# vim: filetype=perl :
