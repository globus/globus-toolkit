#!/usr/bin/perl

use strict;
use Test;

my $test_prog = 'gssapi-expimp-test';

my @tests;

my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-gssapi_expimp_test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}



# Now that the tests are defined, set up the Test to deal with them.
plan tests => 1;

system("$valgrind ./$test_prog");
