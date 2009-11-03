package Uploader;

use Util;
use strict;

sub new() {

  my $proto = shift;
  my $auditdir = shift;
  my $self={};
  bless($self, $proto);
  my $util = Util->new();

  # check if the audit directory had been passed as argument
  if ($util->trim($auditdir) eq "") {
      $util->error("No audit directory specified in constructor of Uploader");
  } else {
      $self->{'auditdir'} = $auditdir;
  }
  return $self;
}

sub loadGram2RecordsIntoDatabase() {

    my $self = shift;
    my $expectErrors = shift;
    my $expectedNumberLeftoverRecords = shift;
    my $util = Util->new();
    my $uploader = "$ENV{GLOBUS_LOCATION}/libexec/globus-gram-audit";
    my $uploaderArgs = "--check --delete --audit-directory " . $self->{'auditdir'};
    
    if (! -e $uploader) {
        $util->error("Can't find " . $uploader . " to upload records");
        return (0 == 1);
    } else {
        # load the records into the database
        my $rcx = system("$uploader $uploaderArgs");
        
        if ($expectErrors == 0) {
            if ($rcx != 0) {
                $util->error("Error during upload, but did not expect errors");
                return (0 == 1);
            }
        } else {
            if ($rcx == 0) {
                $util->error("Expected errors, but uploader returned success");
                return (0 == 1);        
            }
        }
    }
    
    # verify that the number of leftover files in the audit
    # directory fits with the number of expected errors
    $util->debug("Checking for " . $expectedNumberLeftoverRecords .
        " leftover audit record files after upload in " . $self->{'auditdir'});    
    my @leftoverFiles = glob($self->{'auditdir'}."/*.gramaudit");
    my $count = @leftoverFiles;
    if ($count != $expectedNumberLeftoverRecords) {
        $util->error("Expected " . $expectedNumberLeftoverRecords . 
            " leftover files, but " . $count . " files are left over");
        return (0 == 1);                           
    }

    return (0 == 0);
}

1;