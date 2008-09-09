#!/usr/bin/env perl


require 5.005;

use strict;
use Cwd;
use Test::Harness;
use vars qw(@tests);

my $globus_location = $ENV{GLOBUS_LOCATION};

@tests = qw(gssapi-anonymous-test.pl
            compare-name-test.pl
            compare-name-test-rfc2818.pl
            compare-name-test-gt2.pl
            duplicate-name-test.pl
            inquire-names-for-mech-test.pl
            gssapi-delegation-test.pl
            gssapi-limited-delegation-test.pl
            gssapi-delegation-compat-test.pl
            gssapi-acquire-test.pl
            gssapi-context-test.pl gssapi-expimp-test.pl gssapi-inquire-sec-ctx-by-oid-test.pl
            gssapi-import-name.pl
            release-name-test.pl
           );

push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");

runtests(@tests);
