#!/usr/bin/env perl

require 5.005;

use strict;
use Test::Harness;
use vars qw(@tests);

my $globus_location = $ENV{GLOBUS_LOCATION};

@tests = qw(xacml-request-test.pl
            xacml-response-test.pl
            xacml-resource-attribute-test.pl
            xacml-obligation-test.pl
            xacml-server-test.pl
            xacml-client-test.pl
            xacml-io-test.pl
            xacml-fd-test.pl
           );

$ENV{VALGRIND} = 1 if ($ARGV[0] eq '-valgrind');

push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");

runtests(@tests);
