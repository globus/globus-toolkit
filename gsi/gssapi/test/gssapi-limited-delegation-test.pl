#!/usr/bin/perl

use strict;
use Test;

my $test_prog = 'gssapi-limited-delegation-test';

my $diff = 'diff';
my @tests;
my @todo;

my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-gssapi_limited_delegation_test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

system("$valgrind ./$test_prog");
