#! /usr/bin/perl

use Globus::GRAM::Error;
use IO::File;
use Test;

my (@tests, @todo) = ();
my $contact = $ENV{CONTACT_STRING};

my @test_rsls=qw(
	error_bad_directory.rsl
	error_evaluation_failed.rsl
	error_executable_not_found.rsl
	error_executable_permissions.rsl
	error_invalid_cache2.rsl
	error_invalid_cache.rsl
	error_invalid_count.rsl
	error_invalid_gram_myjob.rsl
	error_invalid_jobtype.rsl
	error_invalid_save_state.rsl
	error_invalid_scratch.rsl
	error_invalid_two_phase_commit.rsl
	error_no_state_file.rsl
	error_opening_stderr.rsl
	error_opening_stderr2.rsl
	error_opening_stdout.rsl
	error_opening_stdout2.rsl
	error_rsl_arguments.rsl
	error_rsl_cache.rsl
	error_rsl_directory.rsl
	error_rsl_dryrun.rsl
	error_rsl_environment1.rsl
	error_rsl_environment2.rsl
	error_rsl_evaluation_failed2.rsl
	error_rsl_evaluation_failed.rsl
	error_rsl_executable.rsl
	error_rsl_file_stage_in2.rsl
	error_rsl_file_stage_in3.rsl
	error_rsl_file_stage_in.rsl
	error_rsl_file_stage_in_shared2.rsl
	error_rsl_file_stage_in_shared3.rsl
	error_rsl_file_stage_in_shared.rsl
	error_rsl_file_stage_out2.rsl
	error_rsl_file_stage_out3.rsl
	error_rsl_file_stage_out.rsl
	error_rsl_jobtype.rsl
	error_rsl_myjob.rsl
	error_rsl_remote_io_url.rsl
	error_rsl_restart.rsl
	error_rsl_save_state.rsl
	error_rsl_scratch.rsl
	error_rsl_stderr.rsl
	error_rsl_stderr2.rsl
	error_rsl_stdin.rsl
	error_rsl_stdout.rsl
	error_rsl_stdout2.rsl
	error_rsl_two_phase_commit.rsl
	error_staging_executable.rsl
	error_staging_stdin.rsl
	error_stdin_not_found.rsl
	error_undefined_executable.rsl
);

my @todo_rsls=qw(
    error_invalid_file_cleanup.rsl
    error_invalid_host_count2.rsl
    error_invalid_host_count.rsl
    error_invalid_max_cpu_time.rsl
    error_invalid_max_memory.rsl
    error_invalid_maxtime.rsl
    error_invalid_max_wall_time.rsl
    error_invalid_min_memory.rsl
    error_invalid_project.rsl
    error_invalid_queue.rsl
    error_rsl_host_count.rsl
    error_rsl_max_cpu_time.rsl
    error_rsl_max_memory.rsl
    error_rsl_maxtime.rsl
    error_rsl_max_wall_time.rsl
    error_rsl_min_memory.rsl
    error_rsl_project.rsl
    error_rsl_queue.rsl
);

sub test_rsl
{
    my $rsl_file = shift;
    my $file = new IO::File($rsl_file, '<');
    my $value = <$file>;
    my $error;

    chomp($value);
    $value =~ s/\(\*\s*(\S*)\s*\*\)/$1/;

    $value =~ s/GLOBUS_GRAM_PROTOCOL_ERROR_//;

    $error = eval "Globus::GRAM::Error::$value()";

    system("globusrun -s -r \"$contact\" -f $rsl_file >/dev/null 2>&1");

    $rc = $? >> 8;

    ok($rc, $error->value);
}

foreach(@test_rsls)
{
    push(@tests, "test_rsl(\"$_\")");
}
foreach(@todo_rsls)
{
    push(@tests, "test_rsl(\"$_\")");
    push(@todo, scalar(@tests));
}

plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
