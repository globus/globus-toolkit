#!/usr/bin/env perl

use strict;
use Test::Harness;
require 5.005;
use vars qw(@tests);

my $globus_location = $ENV{GLOBUS_LOCATION};

system('chmod go-rw testcred.pem');

@tests = qw( globus-io-file-test.pl
             globus-io-authorization-test.pl
	     globus-io-tcp-test.pl
	     );

push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");

runtests(@tests);
