#! /usr/bin/env perl

BEGIN { push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl"); }

use strict;
use Test::Harness;

require 5.005;
use vars qw(@tests);

print STDERR <<EOF;
Warning: Do not start a service container while this test script is running.
EOF

my $test_result = 1;
$|=1;

@tests = qw(
    test-fake-seg.pl
);

$test_result = eval { runtests(@tests) };
if(!defined($test_result))
{
    print $@;
    $test_result=1;
}
else
{
    $test_result=0;
}
