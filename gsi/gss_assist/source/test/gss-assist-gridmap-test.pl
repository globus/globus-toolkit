#!/usr/bin/perl

use strict;

my $test_prog = './gss-assist-gridmap';

my ($valgrind) = ('');
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-gss_assist_gridmap_test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

$ENV{GRIDMAP} = "grid-mapfile";

system("$valgrind $test_prog");
