#!/usr/bin/perl

use strict;

my $test_prog = 'nonterminated-export-cred-test';

my @tests;

my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-nonterminated-export-cred-test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}



# Now that the tests are defined, set up the Test to deal with them.

system("$valgrind ./$test_prog");
