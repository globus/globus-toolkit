#!/usr/bin/env perl

# ------------------------------------------------------------------------
# globus_test_check_proxy
#
# ------------------------------------------------------------------------

use strict;
use Utilities;

check_proxy();


# ------------------------------------------------------------------------
# Check proxy
# ------------------------------------------------------------------------
sub check_proxy {
    my $u = new Utilities();
    $u->announce("Checking for proxy");

    $u->command("grid-proxy-info");
    my ($rc, $output) = $u->command("grid-proxy-info -timeleft",1);

    # report failure if less than 60 seconds of proxy time left
    ($output >= 60) ? $u->report("SUCCESS") : $u->report("FAILURE");
}
