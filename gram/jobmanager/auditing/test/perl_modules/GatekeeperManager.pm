package GatekeeperManager;

use Globus::Core::Paths;
use Util;
use strict;

sub new() {

  my $proto = shift;
  my $self={};
  bless($self, $proto);  
  return $self;
}

# start a personal gatekeeper
sub startGatekeeper() {

    my $self = shift;
    my $audit_data_dir = shift;
    my $rc = 0;
    my $contact;
    my $startargs = "-start -log always -auditdir $audit_data_dir";
    my $util = Util->new();
    
    my $personal_gatekeeper = $Globus::Core::Paths::bindir .
        "/globus-personal-gatekeeper";
    
    $util->debug("Stopping personal gatekeepers");
    $util->debug(`$personal_gatekeeper -killall`);
    $util->debug("Starting personal gatekeeper: $personal_gatekeeper $startargs");
    system("$personal_gatekeeper $startargs >/dev/null 2>/dev/null");
    chomp($contact = `$personal_gatekeeper -list`);
    if($? != 0) {
        $util->error("Could not start gatekeeper");
        $rc = 1;
    } else {
        $ENV{CONTACT_STRING} = $contact;
        $util->debug("Started personal gatekeeper with contact \"$contact\"");
    }
    return $rc;
}

# stop the personal gatekeeper
sub stopGatekeeper() {
    
    my $self = shift;
    my $util = Util->new();
    my $command = "globus-personal-gatekeeper -killall >/dev/null 2>&1";
    $util->debug("Stopping personal gatekeeper: $command");
    system("$command");
}


1;