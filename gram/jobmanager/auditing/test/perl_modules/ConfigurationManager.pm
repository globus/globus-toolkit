############################################################################### 
# Handle configuration files. Involved in audit logging in gram2 are
# the following configuration files:
# * database configuration:
#       the values to access the database are store in there
# * job manager configuration
#       globus-gram-audit reads the audit directory from there
#
# For each of the test makes a backup of the existing configuration
# and replaces it with a test configuration. after the test is done the
# backup files are moved back in place
#

package ConfigurationManager;

use Util;
use IO::File;
use strict;

sub new() {

  my $proto = shift;
  my $self={};
  bless($self, $proto);
  
  my $util = Util->new();
  
  $self->{'testdir'} = "$ENV{GLOBUS_LOCATION}/test/globus_gram_job_manager_auditing_test";
  $self->{'jobdir'} = $self->{'testdir'} . "/jobs";
  $self->{'recorddir'} = $self->{'testdir'} . "/records";
  $self->{'auditdir'} = $self->{'testdir'} . "/audit_records";
  $self->{'auditdir'} = $self->{'testdir'} . "/audit_records";
  $self->{'dbconfigscript'} = "$ENV{GLOBUS_LOCATION}/setup/globus/setup-globus-gram-auditing";

  # database configuration
  $self->{'files'}->{'db'}->{'system'} = 
      "$ENV{GLOBUS_LOCATION}/etc/globus-job-manager-audit.conf";
  $self->{'files'}->{'db'}->{'backup'} =  
      $self->{'testdir'}."/globus-job-manager-audit.conf.backup";
  
  # substitution variables in the test configuration files
  $self->{'substVars'}->{'__GLOBUS_LOCATION__'} = "$ENV{GLOBUS_LOCATION}";
  $self->{'substVars'}->{'__AUDIT_DATA_DIR__'} = $self->{'auditdir'};
  $self->{'substVars'}->{'__CURRENT_USER__'} = $util->trim(`whoami`);
  $self->{'substVars'}->{'__EXE_ECHO__'} = $util->trim(`which echo`);
  
  return $self;
}

# install test configuration.
sub installTestConfiguration() {

    my $self = shift;
    my $rc = 0;
    my $util = Util->new();
    
    $util->debug("Installing test configuration"); 
    if (system($self->{'dbconfigscript'}) != 0) {
        $util->error("Error calling $self->{'dbconfigscript'}");
        $rc = 1;
    }

    return $rc;
}

# install buggy test configuration.
sub installBuggyTestConfiguration() {

    my $self = shift;
    my $rc = 0;
    my $util = Util->new();
    
    $util->debug("Installing buggy test configuration (audit v3)"); 
    if (system("$self->{'dbconfigscript'} -v 3") != 0) {
        $util->error("Error calling $self->{'dbconfigscript'}");
        $rc = 1;
    }

    return $rc;
}

# make copies of existing configuration files
sub backupOriginalConfiguration() {

    my $self = shift;
    my $rc = 0;
    my $util = Util->new();
    
    for my $type ( keys %{$self->{'files'}} ) {     
        my $command;
        my $config_system = $self->{'files'}->{$type}->{'system'};
        my $config_backup = $self->{'files'}->{$type}->{'backup'};
        if (-e $config_system) {
            $command = "cp $config_system $config_backup";
            $util->debug("Making backup of original configuration:  $command"); 
            if (system("$command") != 0) {
                $util->error("Unable to make backup of system configuration " .
                    $config_system . " in " . $config_backup);
                $rc = 1;
            }
        }
    }

}

# copy backup configuration files back to system.
# returns 0 in case of success, 1 in case of error.
sub restoreOriginalConfiguration() {

    my $self = shift;
    my $rc = 0;
    my $util = Util->new();
    
    for my $type ( keys %{$self->{'files'}} ) {
    
        my $config_system = $self->{'files'}->{$type}->{'system'};
        my $config_backup = $self->{'files'}->{$type}->{'backup'};
        if (-e $config_backup) {
            my $command = "cp $config_backup $config_system";
            $util->debug("Restoring original configuration:  $command"); 
            if (system("$command") != 0) {
                $util->error("Unable to copy backup "
                    . $config_backup . " back to " . $config_system);
                $rc = 1;
            }
        }
    }
    return $rc;
}

# Get the test base directory
sub getTestDir() {
    
    my $self = shift;
    return $self->{'testdir'};
}

# Get the job directory
sub getJobDir() {
    
    my $self = shift;
    return $self->{'jobdir'};
}

# Get the test-record directory
sub getRecordDir() {
    
    my $self = shift;
    return $self->{'recorddir'};
}

# Get the audit directory
sub getAuditDir() {
    
    my $self = shift;
    return $self->{'auditdir'};
}

# Remove the audit directory and re-create it
sub cleanupAuditDir() {

    my $self = shift;
    my $rc = 0;
    my $util = Util->new();

    $util->debug("Removing and recreating $self->{'auditdir'}"); 
    if (-e $self->{'auditdir'}) {
        if (system("rm -r $self->{'auditdir'}") != 0) {
            $util->error("Cannot remove $self->{'auditdir'}");
            $rc = 1;
        }
    }
    if (system("mkdir $self->{'auditdir'}") != 0) {
        $util->error("Cannot create $self->{'auditdir'}");
        $rc = 1;
    }
    return $rc;
}

# Replace placeholder in the job description files used in this test
# with values. Currently placeholders
sub replaceSubstitutionVars() {

    my $self = shift;
    my @recordFiles = glob "$self->{'recorddir'}/*.in";
    my @jobFiles = glob "$self->{'jobdir'}/*.in";
    my @files = (@recordFiles, @jobFiles);
    
    foreach (@files) {
        my $templateFileName = $_; 
        $_ =~ m/(.*)\.in$/;        my $targetFileName = $1;
        my $templateFile = new IO::File("$templateFileName", '<');
        my $targetFile = new IO::File("$targetFileName", '>');
        while(<$templateFile>) {
            # Substitute placeholders with values
            while (my($placeholder,$value) = each(%{$self->{'substVars'}})) {
                s/$placeholder/$value/;
            }
            $targetFile->print($_);
        }
    }
}

1;
