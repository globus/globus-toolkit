#!/usr/bin/env perl

use strict;

my $test_prog = 'gssapi-acquire-test';

my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-gssapi_acquire_test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

system("$valgrind ./$test_prog");
