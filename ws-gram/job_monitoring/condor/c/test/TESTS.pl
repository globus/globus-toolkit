#! /usr/bin/env perl

BEGIN { push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl"); }

use strict;
use Test::Harness;

require 5.005;
use vars qw(@tests);

my $test_result = 1;
$|=1;

@tests = qw(
    test-condor-seg.pl
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
