#! /usr/bin/env perl

BEGIN { push(@INC, "./perl_modules"); }

use strict;
use ConfigurationManager;
use Uploader;
use Util;

my $configurationManager = ConfigurationManager->new();
my $auditdir = $configurationManager->getAuditDir();
my $uploader = Uploader->new($auditdir);
my $util = Util->new();
my $expectErrors = 0;
my $expectedNumberLeftoverRecords = 0;

# swap in test configuration
$configurationManager->backupOriginalConfiguration();
$configurationManager->installTestConfiguration();

# make sure the test audit directory is not empty.
# this test expects audit records from the submission test in the audit directory
my $numberOfRecords = getNumberFilesInAuditDir();
if ($numberOfRecords == 0) {
    $util->error("Expecting records in the audit directoryfrom the " .
        "submission test but didn't find any");
    cleanupAndExit(1);    
} else {
    $util->debug("Loading up $numberOfRecords audit records into the database");
}

if (!$uploader->loadGram2RecordsIntoDatabase($expectErrors, $expectedNumberLeftoverRecords)) {
    $util->error("Upload of record failed. This should have succeeded");
    cleanupAndExit(1);    
}

cleanupAndExit(0);

############################ Helper methods ####################################

# return the number of files in the audit directory
sub getNumberFilesInAuditDir {

    my @audit_record_files =
        glob($auditdir . "/*.gramaudit");
    my $count = @audit_record_files;
    return $count;
}

sub cleanupAndExit {

    my $rc = shift;
    # restore original configuration
    $configurationManager->restoreOriginalConfiguration();
    exit $rc;
}
