#!/usr/bin/env perl

BEGIN {
    BEGIN { push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl"); }
    BEGIN { push(@INC, "./perl_modules"); }
}

use strict;
use Test::Harness;
use ConfigurationManager;
use GatekeeperManager;
use Cwd;

my $rc = 0;
my $stop_gatekeeper = 0;

$ENV{X509_CERT_DIR} = cwd();
$ENV{X509_USER_PROXY} = "testproxy.pem";
system('chmod go-rw testproxy.pem');

# check that environment variable GLOBUS_LOCATION is set
if (! -d $ENV{GLOBUS_LOCATION}) {
    print "Environment variable GLOBUS_LOCATION is not defined => no test";
    $rc = 1;
} else {
    my $cm = new ConfigurationManager();
    GatekeeperManager::startGatekeeper($cm->getAuditDir());
    $stop_gatekeeper = 1;

    my @tests = qw(
            globus-gram-job-manager-auditing-job-submission-test.pl
            globus-gram-job-manager-auditing-upload-success-test.pl
            globus-gram-job-manager-auditing-tg-job-submission-test.pl
            globus-gram-job-manager-auditing-upload-success-test.pl
            globus-gram-job-manager-auditing-upload-failure-test.pl );
    runtests(@tests);
}

exit (0 != $rc);

END {
    GatekeeperManager::stopGatekeeper();
}
