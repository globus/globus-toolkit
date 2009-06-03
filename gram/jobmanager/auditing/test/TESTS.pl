#!/usr/bin/env perl

use strict;
use Test::Harness;

my $rc = 0;

# check that environment variable GLOBUS_LOCATION is set
if (! -d $ENV{GLOBUS_LOCATION}) {
    print "Environment variable GLOBUS_LOCATION is not defined => no test";
    $rc = 1;
} else {
    my @tests = qw(
            globus-gram-job-manager-auditing-job-submission-test.pl
            globus-gram-job-manager-auditing-upload-success-test.pl
            globus-gram-job-manager-auditing-tg-job-submission-test.pl
            globus-gram-job-manager-auditing-upload-success-test.pl
            globus-gram-job-manager-auditing-upload-failure-test.pl );
    runtests(@tests);
}

exit (0 != $rc);
