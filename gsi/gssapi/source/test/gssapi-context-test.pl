#!/usr/bin/perl

use strict;
use Test::More;

my $test_prog = 'gssapi-context-test';

my @tests;

my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-gssapi_context_test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

push(@tests, "ok(system(\"$valgrind ./$test_prog\") == 0, \$test_prog)");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests);

# And run them all.
foreach (@tests)
{
    eval "$_";
}
