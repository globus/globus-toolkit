#!/usr/bin/env perl

use strict;

my $rc = 0;

# check that environment variable GLOBUS_LOCATION is set
if (! -d $ENV{GLOBUS_LOCATION}) {
    print "Environment variable GLOBUS_LOCATION is not defined => no test";
    $rc = 1;
} else {
    $rc += runTest("globus-gram-job-manager-auditing-job-submission-test.pl");
    $rc += runTest("globus-gram-job-manager-auditing-upload-success-test.pl");
    $rc += runTest("globus-gram-job-manager-auditing-upload-failure-test.pl");
}

exit (0 != $rc);

sub runTest() {

    my $test_name = shift;
    print "Running $test_name ...\n";
    my $rcx = system("./$test_name");
    print STDOUT (0 == $rcx) ? "ok\n\n" : "failed\n\n";
    return $rcx;
}
