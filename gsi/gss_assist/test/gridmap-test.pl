#!/usr/bin/env perl

use strict;
use Test;
use Globus::Testing::Utilities;

my @tests;
my @todo;

my $test_prog = './gridmap-test';

Globus::Testing::Utilities::testcred_setup() || die "Unable to set up test certs
";


my ($valgrind) = ('');
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-gridmap_test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

exit(system("$valgrind $test_prog") / 256);
