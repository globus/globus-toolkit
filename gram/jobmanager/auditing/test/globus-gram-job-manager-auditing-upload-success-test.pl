#! /usr/bin/env perl

BEGIN { push(@INC, "./perl_modules"); }

use strict;
use Uploader;
use Util;
use ConfigurationManager;

my $configurationManager = ConfigurationManager->new();
my $auditdir = $configurationManager->getAuditDir();
my $uploader = Uploader->new($auditdir);
my $expectErrors = 0;
my $expectedNumberLeftoverRecords = 0;

print "1..1\n";

# make sure the test audit directory is not empty.
# this test expects audit records from the submission test in the audit directory
my $numberOfRecords = getNumberFilesInAuditDir();
if ($numberOfRecords == 0) {
    fail("Expecting records in the audit directory from the " .
            "submission test but didn't find any\n");
    exit(0);
} else {
    Util::debug("Loading up $numberOfRecords audit records into the database");
}

if (!$uploader->loadGram2RecordsIntoDatabase(
        $configurationManager->getGoodConfiguration(),
        $expectErrors,
        $expectedNumberLeftoverRecords)) {
    fail ("Upload of record failed. This should have succeeded\n");
    exit(0);
}

print "ok\n";
exit(0);

############################ Helper methods ####################################

# return the number of files in the audit directory
sub getNumberFilesInAuditDir {
    my @audit_record_files =
        glob($auditdir . "/*.gramaudit");
    my $count = @audit_record_files;
    return $count;
}

sub fail {
    my $reason = $_[0];
    print "not ok\n";
    print STDERR $reason;
}
