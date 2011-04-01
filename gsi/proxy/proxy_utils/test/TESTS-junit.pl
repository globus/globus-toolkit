#! /usr/bin/perl

require 5.005;

use warnings;
use strict;
use TAP::Harness::JUnit;
use Cwd;

my $cwd = getcwd();
$ENV{X509_CERT_DIR} = $cwd;
$ENV{X509_USER_CERT} = "$cwd/usercert.pem";
$ENV{X509_USER_KEY} = "$cwd/userkey.pem";

chmod 0600, $ENV{X509_USER_KEY};

my @tests = qw(grid-proxy-utils-test.pl);


my $harness = TAP::Harness::JUnit->new({
        merge => 1,
        xmlfile => 'globus-proxy-utils-test.xml' });
$harness->runtests(@tests);
;
