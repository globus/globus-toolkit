#! /usr/bin/env perl

BEGIN { push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl"); }
BEGIN { push(@INC, "./perl_modules"); }

print "1..1\n";

use strict;
use Cwd;
require 5.005;
use ConfigurationManager;
use Util;

my $configurationManager = ConfigurationManager->new();

$ENV{X509_CERT_DIR} = cwd();
$ENV{X509_USER_PROXY} = "shibproxy.pem";
system('chmod go-rw shibproxy.pem'); 

# make sure the test audit directory is empty 
$configurationManager->cleanupAuditDir();

# substitute variables
$configurationManager->replaceSubstitutionVars();

# get list of job files to be submitted
my @jobFiles = glob($configurationManager->getJobDir()."/*.rsl");
my $numberOfJobs = @jobFiles;
if ($numberOfJobs == 0) {
    print "not ok #No jobs to submit. Check job directory for *.rsl files\n";
    exit(0);
}

# submit the jobs
foreach (@jobFiles) {    my $command = "globusrun -s -r \"$ENV{CONTACT_STRING}\" -f $_";
    Util::debug("Submitting job: $command");
    `$command`;
}

# check 30 seconds if the audit-record file that fits to the
# submitted job was created. If not assume that an error occured
my $foundRecords = 0;
my @auditRecordFiles;

# check if an audit record file for each job was created
my $auditdir = $configurationManager->getAuditDir();
Util::debug("Looking for $numberOfJobs audit record in $auditdir");
for (my $i=0; $i<30; $i++) {
    @auditRecordFiles = glob($auditdir."/*.gramaudit");
    my $count = @auditRecordFiles;
    if ($count == $numberOfJobs) {
        Util::debug("Found $count audit records");
        $foundRecords = 1;
        last;
    } elsif ($count > $numberOfJobs) {
        print "not ok #Found $count audit records. That's too many\n";
        exit(0);
    } else {
        Util::debug("Found $count audit records");
        sleep(1);
    } 
}

# if the audit-record file was not found
if (!$foundRecords) {
    print "not ok #No audit record file per job created by Gram\n";
    exit(0);
}

# Check that audit records contain the tg gateway username
foreach (glob($auditdir."/*.gramaudit")) {
    my $file = $_;
    my $line;
    my $gateway_user;

    local(*F);

    open(F, "<$file");
    chomp($line = <F>);

    $gateway_user = (split(/,/, $line))[15];
    if ($gateway_user ne '"testuser@example.org"') {
        print "not ok # gateway_user = $gateway_user\n";
        exit(0);
    }
}

print "ok\n";
exit(0);
