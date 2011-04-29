#! /usr/bin/env perl

BEGIN
{
    push(@INC, $ENV{'GLOBUS_LOCATION'} . '/lib/perl');
}

use strict;
use Test::More;
use Globus::Core::Paths;
use IPC::Open2;
use POSIX qw(pause);

$^W = 1;

my $script = $Globus::Core::Paths::libexecdir . "/globus-job-manager-script.pl";
my @tests = qw(test_interactive_quit test_interactive_poll);

plan tests => 3;
test_interactive_quit();
test_interactive_poll();
test_interactive_multipoll();

sub test_interactive_quit
{
    my ($child_out, $child_in);
    my $pid;
    my $out;

    $pid = open2(
            $child_out, $child_in,
            $script,
            '-m', 'fork',
            '-c', 'interactive');

    print $child_in "quit\n\n";
    waitpid $pid, 0;
    ok($? == 0, "test_interactive_quit");
}

sub test_interactive_poll
{
    my ($child_out, $child_in);
    my $pid;
    my $dummy_pid;
    my $out;
    my $result;

    $pid = open2(
            $child_out, $child_in,
            $script,
            '-m', 'fork',
            '-c', 'interactive');

    $dummy_pid = fork();

    $result = defined($dummy_pid);
    if (!$result)
    {
        goto FAIL;
    }
    elsif ($dummy_pid == 0)
    {
        pause();
        exit(0);
    }
    print $child_in "poll\n";
    print $child_in "\$description = { jobid => [ '$dummy_pid' ] };\n\n";
    while (($_ = <$child_out>) ne "\n")
    {
        if ($_ =~ /^GRAM_SCRIPT_LOG/)
        {
            next;
        }
        $result = ($_ eq "GRAM_SCRIPT_JOB_STATE:2\n");
        if (!$result)
        {
            kill 'TERM', $dummy_pid;
            waitpid($dummy_pid, 0);
            print $child_in "quit\n\n";
            waitpid($pid, 0);
            goto FAIL;
        }
    }
    kill 'TERM', $dummy_pid;
    waitpid($dummy_pid, 0);

    print $child_in "poll\n";
    print $child_in "\$description = { jobid => [ '$dummy_pid' ] };\n\n";
    while (($_ = <$child_out>) ne "\n")
    {
        if ($_ =~ /^GRAM_SCRIPT_LOG/)
        {
            next;
        }
        $result = $_ eq "GRAM_SCRIPT_JOB_STATE:8\n";

        if (!$result)
        {
            goto FAIL;
        }
    }
    print $child_in "quit\n\n";

    waitpid $pid, 0;
    $result = ($? == 0);

FAIL:
    ok($result, 'test_interactive_poll');
}

sub test_interactive_multipoll
{
    my ($child_out, $child_in);
    my $pid;
    my $dummy_pid;
    my $out;
    my $result;

    $pid = open2(
            $child_out, $child_in,
            $script,
            '-m', 'fork',
            '-c', 'interactive');

    $dummy_pid = fork();
    $result = defined($dummy_pid);

    if (! $result)
    {
        goto FAIL;
    }
    elsif ($dummy_pid == 0)
    {
        pause();
        exit(0);
    }

    for (my $i = 0; $i < 100; $i++)
    {
        print $child_in "poll\n";
        print $child_in "\$description = { jobid => [ '$dummy_pid' ] };\n\n";
        while (($_ = <$child_out>) ne "\n")
        {
            if ($_ =~ m/^GRAM_SCRIPT_LOG/)
            {
                next;
            }

            $result = $_ eq "GRAM_SCRIPT_JOB_STATE:2\n";
            if (!$result)
            {
                kill 'TERM', $dummy_pid;
                waitpid($dummy_pid, 0);
                print $child_in "quit\n\n";
                waitpid($pid, 0);
                goto FAIL;
            }
        }
    }
    kill 'TERM', $dummy_pid;
    waitpid($dummy_pid, 0);

    print $child_in "poll\n";
    print $child_in "\$description = { jobid => [ '$dummy_pid' ] };\n\n";
    while (($_ = <$child_out>) ne "\n")
    {
        if ($_ =~ m/^GRAM_SCRIPT_LOG/)
        {
            next;
        }
        $result = $_ eq "GRAM_SCRIPT_JOB_STATE:8\n";
        if (!$result)
        {
            goto FAIL;
        }
    }
    print $child_in "quit\n\n";

    waitpid $pid, 0;
    $result = ($? == 0);
FAIL:
    ok($result, 'test_interactive_multipoll');
}
