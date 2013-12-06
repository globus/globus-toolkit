#!/usr/bin/perl

use strict;

my $test_prog = 'gssapi-delegation-test';

my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-gssapi_delegation_test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

system("$valgrind ./$test_prog");
