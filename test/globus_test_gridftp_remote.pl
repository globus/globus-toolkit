#!/usr/bin/env perl

# ------------------------------------------------------------------------
# globus_test_gridftp_remote
# ------------------------------------------------------------------------

use strict;
use Utilities;

test_gridftp_remote();


# ------------------------------------------------------------------------
# Test GridFTP remote
# ------------------------------------------------------------------------
sub test_gridftp_remote {
    my $u = new Utilities();
    $u->announce("Testing GridFTP remotely");

    my $output;
    my $remote = $u->remote;
    my $hostname = $u->hostname;

    $u->command(". env.sh");

    $u->command("globus-url-copy \\
        gsiftp://$remote/etc/termcap \\
        gsiftp://$hostname/tmp/gridftp.test");
    $output = $u->command("head /tmp/gridftp.test");
    $output =~ "^#" ? $u->report("ok") : $u->report("not ok");

    $u->command("rm -f /tmp/gridftp.test");
}
