#!/usr/bin/env perl

use strict;
use Test::Harness;
require 5.005;
use vars qw(@tests);

my $globus_location = $ENV{GLOBUS_LOCATION};

system('chmod go-rw testcred.pem');

@tests = qw(gss-assist-impexp-test.pl
            gss-assist-auth-test.pl
            );

push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");

runtests(@tests);
