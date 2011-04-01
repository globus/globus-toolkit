#! /usr/bin/perl


use strict;
use warnings;
use TAP::Harness::JUnit;
require 5.005;
use vars qw(@tests);

if (system("grid-proxy-info -exists") != 0)
{
    print "Cannot run tests without a GSI proxy\n";
}

@tests = qw(gss-assist-impexp-test.pl
            gss-assist-auth-test.pl
            gss-assist-gridmap-test.pl
            gridmap-test.pl
            gridmap-tools-test.pl
            );

my $harness = TAP::Harness::JUnit->new({
        merge => 1,
        xmlfile => 'globus-gss-assist-test.xml' });
$harness->runtests(@tests);

