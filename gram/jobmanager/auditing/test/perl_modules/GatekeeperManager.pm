package GatekeeperManager;

use Globus::Core::Paths;
use Util;
use strict;

my $personal_gatekeeper = $Globus::Core::Paths::bindir
   . "/globus-personal-gatekeeper";

# start a personal gatekeeper
sub startGatekeeper($) {
    my $audit_data_dir = shift;
    my $rc = 0;
    my $contact;
    my $startargs = "-start -auditdir $audit_data_dir";

    if (exists $ENV{X509_CERT_DIR})
    {
        $startargs .= " -x509-cert-dir $ENV{X509_CERT_DIR}"
    }
    
    Util::debug("Starting personal gatekeeper: $personal_gatekeeper $startargs");
    chomp($contact = `$personal_gatekeeper $startargs`);
    $contact =~ s/GRAM contact: //;

    if($contact eq '') {
        Util::error("Could not start gatekeeper");
        $rc = 1;
    } else {
        $ENV{CONTACT_STRING} = $contact;
        Util::debug("Started personal gatekeeper with contact \"$contact\"");
    }
    return $rc;
}

# stop the personal gatekeeper
sub stopGatekeeper() {
    my $command = "globus-personal-gatekeeper -kill \"$ENV{CONTACT_STRING}\" >/dev/null 2>&1";
    Util::debug("Stopping personal gatekeeper: $command");
    system("$command");
}

1;
