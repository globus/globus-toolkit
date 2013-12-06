#! /usr/bin/perl

@GLOBUS_PERL_INITIALIZER@

require 5.005;

use warnings;
use strict;
use Test::Harness;
use Globus::Testing::Utilities;

Globus::Testing::Utilities::testcred_setup(1) || die("Unable to set up creds");

my @tests = qw(grid-proxy-utils-test.pl proxy-order-test.pl);

runtests(@tests);

