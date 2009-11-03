#! /usr/bin/env perl

BEGIN { push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl"); }
BEGIN { push(@INC, "./perl_modules"); }

use strict;
use Cwd;
require 5.005;
use ConfigurationManager;
use GatekeeperManager;
use Util;

my $configurationManager = ConfigurationManager->new();
my $gatekeeperManager = GatekeeperManager->new();
my $util = Util->new();
my $killGatekeeper = 0;              # kill the gatekeeper at the end (1=yes,0=no)

if(0 != system("grid-proxy-info -exists -hours 2 2>/dev/null") / 255) {
    $ENV{X509_CERT_DIR} = cwd();
    $ENV{X509_USER_PROXY} = "testcred.pem";
    system('chmod go-rw testcred.pem'); 
}

# make sure the test audit directory is empty 
$configurationManager->cleanupAuditDir();

# substitute variables
$configurationManager->replaceSubstitutionVars();

# get list of job files to be submitted
my @jobFiles = glob($configurationManager->getJobDir()."/*.rsl");
my $numberOfJobs = @jobFiles;
if ($numberOfJobs == 0) {
    $util->error("No jobs to submit. Check job directory for *.rsl files");
    cleanupAndExit($killGatekeeper, 1);
}

# start a personal gatekeeper for testing purpose
$gatekeeperManager->startGatekeeper($configurationManager->getAuditDir());
$killGatekeeper = 1;

# submit the jobs
foreach (@jobFiles) {    my $command = "globusrun -s -r \"$ENV{CONTACT_STRING}\" -f $_";
    $util->debug("Submitting job: $command");
    `$command`;
}

# check 30 seconds if the audit-record file that fits to the
# submitted job was created. If not assume that an error occured
my $foundRecords = 0;
my @auditRecordFiles;

# check if an audit record file for each job was created
my $auditdir = $configurationManager->getAuditDir();
$util->debug("Looking for $numberOfJobs audit record in $auditdir");
for (my $i=0; $i<30; $i++) {
    @auditRecordFiles = glob($auditdir."/*.gramaudit");
    my $count = @auditRecordFiles;
    if ($count == $numberOfJobs) {
        $util->debug("Found $count audit records");
        $foundRecords = 1;
        last;
    } elsif ($count > $numberOfJobs) {
        $util->error("Found $count audit records. That's too many");
        cleanupAndExit($killGatekeeper, 1);
    } else {
        $util->debug("Found $count audit records");
        sleep(1);
    } 
}

# if the audit-record file was not found
if (!$foundRecords) {
    $util->error("No audit record file per job created by Gram");
    cleanupAndExit($killGatekeeper, 1);
}

cleanupAndExit($killGatekeeper, 0);

############################ Helper methods ####################################

# stops and removes data of the personal gatekeeper and returns the
# success of the script (0=success, 1=failure)
sub cleanupAndExit {

    my $killGatekeeper = shift;
    my $rc = shift;
    if($killGatekeeper) {
	    $gatekeeperManager->stopGatekeeper();
    }
    exit $rc;
}
