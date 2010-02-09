#! /usr/bin/env perl
#

use strict;
use POSIX;
use Test;
use IO::File;
use File::Path;

my $test_exec = './job-status-with-info-test';

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}
if ($ENV{CONTACT_STRING} eq "")
{
    die "CONTACT_STRING not set";
}

@INC = (@INC, "$gpath/lib/perl");

my @tests;
my @todo;
my $testno=1;

sub job_status_with_info_test
{
    my ($errors,$rc) = ("",0);
    my $valgrind = "";

    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-globus_gram_client_two_phase_commit_test" . $testno++ . ".log";
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
        }
    }
    system("$valgrind $test_exec \"$ENV{CONTACT_STRING}\"");
    $rc = $?>> 8;
    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }
    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        ok($errors, 'success');
    }

}

push(@tests, "job_status_with_info_test");

# Now that the tests are defined, set up the Test to deal with them.
#plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
