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
my $backed_up = 0;
my %recordFiles = (
    "ok1"  => $recorddir . "/ok.gramaudit",
    "bad1" => $recorddir . "/too-few-fields.gramaudit",
    "bad2" => $recorddir . "/invalid-queued-timestamp.gramaudit",
    "bad3" => $recorddir . "/non-existing-username.gramaudit",
);

print "1..1\n";

Util::debug("-- Trying 2 buggy records. expecting errors and 2 leftover files");
$expectErrors = 1;
$expectedNumberLeftoverRecords = 2;
tryUpload($expectErrors,
    $expectedNumberLeftoverRecords,
    $configurationManager->getGoodConfiguration(),
    ($recordFiles{"bad1"}, $recordFiles{"bad2"}));

Util::debug("-- Trying 1 ok and 1 buggy record. expecting errors and 1 leftover file");
$expectErrors = 1;
$expectedNumberLeftoverRecords = 1;
tryUpload(
    $expectErrors,
    $expectedNumberLeftoverRecords,
    $configurationManager->getGoodConfiguration(),
    ($recordFiles{"ok1"}, $recordFiles{"bad2"}));

Util::debug("-- Trying 1 record where record file owner != local user id as defined in the record");
$expectErrors = 1;
$expectedNumberLeftoverRecords = 1;
tryUpload(
    $expectErrors,
    $expectedNumberLeftoverRecords,
    $configurationManager->getGoodConfiguration(),
    ($recordFiles{"bad3"}));

Util::debug("-- Trying invalid audit config");
$expectErrors = 1;
$expectedNumberLeftoverRecords = 1;
tryUpload(
    $expectErrors,
    $expectedNumberLeftoverRecords,
    $configurationManager->getBadConfiguration(),
    ($recordFiles{"ok1"}));

print "ok\n";
exit(0);

############################ Helper methods ####################################

sub tryUpload {
	
    my $expectErrors = shift;
    my $numberLeftoverRecords = shift;
    my $conf = shift;
    my @recordArray = @_;
    my $numberOfRecords = @recordArray;
    
    # cleanup the audit directory
    $configurationManager->cleanupAuditDir();

    # make sure the test audit directory is empty 
    if (getNumberFilesInAuditDir() != 0) {
        print "not ok #Audit directory not empty\n";
        exit(0);
    }

    foreach(@recordArray) {
        system("cp $_ $auditdir");
    }

    # make sure the test records are in place
    if (getNumberFilesInAuditDir() != $numberOfRecords) {
        print "not ok #Audit directory not empty\n";
        exit(0);
    }
        
    if (!$uploader->loadGram2RecordsIntoDatabase($conf, $expectErrors, $numberLeftoverRecords)) {
        print "not ok #Upload of record did not work as expected.\n";
        exit(0);
    }
}

# return the number of files in the audit directory
sub getNumberFilesInAuditDir {

    my @audit_record_files = glob($auditdir . "/*.gramaudit");
    my $count = @audit_record_files;
    return $count;
}
