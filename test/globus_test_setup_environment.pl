#!/usr/bin/env perl

# ------------------------------------------------------------------------
# globus_test_setup_environment
# ------------------------------------------------------------------------

use strict;
use Utilities;

setup_environment();

# ----------------------------------------------------------------------
# Setup environment
# ----------------------------------------------------------------------
sub setup_environment {
    my $u = new Utilities;
    $u->announce("Setting up environment");

    $u->inform("Hostname: ".$u->hostname);
    $u->inform("Username: ".$u->username);

    $u->command("rm -f env.sh env.csh");

    my $globus = $u->globus;

    if (! $globus) {
        $u->debug("TEST_GLOBUS_LOCATION is *not* set");
        $u->inform("TEST_GLOBUS_LOCATION is not set.");
        $u->report("FAILURE");
    }
    else {
        $u->debug("TEST_GLOBUS_LOCATION is set to $globus");
        $u->inform("Setting GLOBUS_LOCATION = $globus");
        $ENV{GLOBUS_LOCATION} = "$globus";
        $u->command("echo \$GLOBUS_LOCATION");
        $u->command("echo \"export GLOBUS_LOCATION=$globus\" >> env.sh", 1);
        $u->command("echo \"setenv GLOBUS_LOCATION \'$globus\'\" >> env.csh", 1);
        $u->report("SUCCESS");
    }
}
