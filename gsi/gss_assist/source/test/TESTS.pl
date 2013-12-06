#! /usr/bin/perl

@GLOBUS_PERL_INITIALIZER@

use strict;
use warnings;
use Test::Harness;
require 5.005;
use vars qw(@tests);
use Globus::Testing::Utilities;

Globus::Testing::Utilities::testcred_setup() ||
    die "Unable to set up test certs"

@tests = qw(gss-assist-impexp-test.pl
            gss-assist-auth-test.pl
            gss-assist-gridmap-test.pl
            gridmap-test.pl
            gridmap-tools-test.pl
            );

runtests(@tests);
