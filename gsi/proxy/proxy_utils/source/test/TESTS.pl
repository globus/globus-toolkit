#! /usr/bin/perl

require 5.8.0;

use warnings;
use strict;
use Test::Harness;

my @tests = qw(grid-proxy-utils-test.pl proxy-order-test.pl);

runtests(@tests);
