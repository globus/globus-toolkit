#! /usr/bin/env perl
#
# Activate and deactivate the client library

use strict;
use POSIX;
use Test;

my $test_exec = 'globus-gram-client-activate-test';

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my @tests;
my @todo;
my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-globus_gram_client_activate_test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

sub activate_test
{
    my ($errors,$rc) = ("",0);
    my ($output);

    system("$valgrind $test_exec >/dev/null");
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
## Test #1: activate/deactivate the GRAM client library
push(@tests, "activate_test");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
