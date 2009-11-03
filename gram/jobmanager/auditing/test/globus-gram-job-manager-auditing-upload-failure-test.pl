#! /usr/bin/env perl

BEGIN { push(@INC, "./perl_modules"); }

use strict;
use ConfigurationManager;
use Uploader;
use Util;

my $expectErrors;
my $expectedNumberLeftoverRecords;
my $configurationManager = ConfigurationManager->new();
my $recorddir = $configurationManager->getRecordDir();
my $auditdir = $configurationManager->getAuditDir();
my $uploader = Uploader->new($auditdir);
my $util = Util->new();
my %recordFiles = (
    "ok1"  => $recorddir . "/ok.gramaudit",
    "bad1" => $recorddir . "/too-few-fields.gramaudit",
    "bad2" => $recorddir . "/invalid-queued-timestamp.gramaudit",
    "bad3" => $recorddir . "/non-existing-username.gramaudit",
);

# swap in test configuration and cleanup audit directory
$configurationManager->backupOriginalConfiguration();
$configurationManager->installTestConfiguration();

$util->debug("-- Trying 2 buggy records. expecting errors and 2 leftover files");
$expectErrors = 1;
$expectedNumberLeftoverRecords = 2;
tryUpload($expectErrors, $expectedNumberLeftoverRecords, ($recordFiles{"bad1"}, $recordFiles{"bad2"}));

$util->debug("-- Trying 1 ok and 1 buggy record. expecting errors and 1 leftover file");
$expectErrors = 1;
$expectedNumberLeftoverRecords = 1;
tryUpload($expectErrors, $expectedNumberLeftoverRecords, ($recordFiles{"ok1"}, $recordFiles{"bad2"}));

$util->debug("-- Trying 1 record where record file owner != local user id as defined in the record");
$expectErrors = 1;
$expectedNumberLeftoverRecords = 1;
tryUpload($expectErrors, $expectedNumberLeftoverRecords, ($recordFiles{"bad3"}));

$util->debug("-- Trying invalid audit version (v3)");
$expectErrors = 1;
$expectedNumberLeftoverRecords = 1;
$configurationManager->installBuggyTestConfiguration();
tryUpload($expectErrors, $expectedNumberLeftoverRecords, ($recordFiles{"ok1"}));

cleanupAndExit(0);

############################ Helper methods ####################################

sub tryUpload {
	
    my $expectErrors = shift;
    my $numberLeftoverRecords = shift;
    my @recordArray = @_;
    my $numberOfRecords = @recordArray;
    
    # cleanup the audit directory
    $configurationManager->cleanupAuditDir();

    # make sure the test audit directory is empty 
    if (getNumberFilesInAuditDir() != 0) {
        $util->error("Audit directory not empty");
        cleanupAndExit(1);    
    }

    foreach(@recordArray) {
        system("cp $_ $auditdir");
    }

    # make sure the test records are in place
    if (getNumberFilesInAuditDir() != $numberOfRecords) {
        $util->error("Audit directory not empty");
        cleanupAndExit(1);    
    }
        
    if (!$uploader->loadGram2RecordsIntoDatabase($expectErrors, $numberLeftoverRecords)) {
        $util->error("Upload of record did not work as expected.");
        cleanupAndExit(1);    
    }
}

# return the number of files in the audit directory
sub getNumberFilesInAuditDir {

    my @audit_record_files = glob($auditdir . "/*.gramaudit");
    my $count = @audit_record_files;
    return $count;
}

sub cleanupAndExit {

    my $rc = shift;
    # restore original configuration
    $configurationManager->restoreOriginalConfiguration();
    exit $rc;
}
