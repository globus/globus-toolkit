#!/usr/bin/perl

use strict;
use TAP::Harness::JUnit;
require 5.005;
use vars qw(@tests);

@tests = qw( globus-openssl-error-test.pl
	     );

my $harness = TAP::Harness::JUnit->new(
    { merge => 1, xmlfile => 'globus-openssl-error-test.xml' });

$harness->runtests(@tests);
