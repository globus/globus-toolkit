#!/usr/bin/env perl

require 5.005;

use strict;
use Test::Harness;

my $globus_location = $ENV{GLOBUS_LOCATION};
my @tests = qw(grid-proxy-utils-test.pl);

push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");

runtests(@tests);

