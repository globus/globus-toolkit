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
use File::Copy qw(copy);
use strict;

sub new {

  my $proto = shift;
  my $self={};
  bless($self, $proto);
  
  $self->{'testdir'} = "$ENV{GLOBUS_LOCATION}/test/globus_gram_job_manager_auditing_test";
  $self->{'jobdir'} = $self->{'testdir'} . "/jobs";
  $self->{'recorddir'} = $self->{'testdir'} . "/records";
  $self->{'configdir'} = $self->{'testdir'} . "/configuration";
  $self->{'auditdir'} = $self->{'testdir'} . "/audit_records";

  # substitution variables in the test configuration files
  $self->{'substVars'}->{'__GLOBUS_LOCATION__'} = "$ENV{GLOBUS_LOCATION}";
  $self->{'substVars'}->{'__AUDIT_DATA_DIR__'} = $self->{'auditdir'};
  $self->{'substVars'}->{'__CURRENT_USER__'} = (getpwuid($>))[0];
  $self->{'substVars'}->{'__CURRENT_TIME__'} = scalar(localtime);
  $self->{'substVars'}->{'__EXE_ECHO__'} = Util::trim(`which echo`);

  $self->{'conf'} = "$ENV{GLOBUS_LOCATION}/etc/globus-job-manager-audit.conf";
  $self->{'goodconf'} = "$self->{testdir}/globus-job-manager-audit.conf";
  $self->{'badconf'} = "$self->{testdir}/globus-job-manager-audit-bad.conf";
  
  return $self;
}


sub getGoodConfiguration() {
    my $self = shift;

    copy($self->{conf}, $self->{goodconf});

    return $self->{'goodconf'};
}

sub getBadConfiguration() {
    my $self = shift;
    my $in = new IO::File("<" . $self->{conf});
    my $out = new IO::File(">" . $self->{badconf});

    while (<$in>)
    {
        $_ =~ s/^DATABASE:(.*)/DATABASE:bad$1/;
        $out->print($_);
    }
    $in->close();
    $out->close();

    return $self->{badconf};
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

    Util::debug("Removing and recreating $self->{'auditdir'}"); 
    if (-e $self->{'auditdir'}) {
        if (system("rm -r $self->{'auditdir'}") != 0) {
            Util::error("Cannot remove $self->{'auditdir'}");
            $rc = 1;
        }
    }
    if (system("mkdir $self->{'auditdir'}") != 0) {
        Util::error("Cannot create $self->{'auditdir'}");
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
