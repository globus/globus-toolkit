#! /usr/bin/perl

require 5.005;

use warnings;
use strict;
use TAP::Harness::JUnit;

use vars qw(@tests);

@tests = qw(test_pci.pl);

my $harness = TAP::Harness::JUnit->new({
            merge => 1,
                    xmlfile => 'globus-proxy-ssl-test.xml' });
$harness->runtests(@tests);
