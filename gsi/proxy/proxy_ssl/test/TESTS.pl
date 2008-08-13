#!/usr/bin/env perl

use strict;
use Test::Harness;
require 5.005;
use vars qw(@tests);

my $globus_location = $ENV{GLOBUS_LOCATION};

@tests = qw(test_pci.pl);

push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");

runtests(@tests);
