#!/usr/bin/env perl

# ------------------------------------------------------------------------
# globus_test_gridftp_local
# ------------------------------------------------------------------------

use strict;
use Utilities;

test_gridftp_local();


# ------------------------------------------------------------------------
# Test GridFTP local
# ------------------------------------------------------------------------
sub test_gridftp_local {
    my $u = new Utilities();
    $u->announce("Testing GridFTP locally");

    my $output;

    $u->command(". env.sh");

    $u->command("killall in.ftpd",0,1);
    $u->command("in.ftpd -a -s -p 9998 > /dev/null &");
    $u->command("in.ftpd -a -s -p 9999 > /dev/null &");
    $output = $u->command("grid-cert-info -subject",1);
    $u->command("globus-url-copy -s \"$output\" \\
        gsiftp://localhost:9998/etc/termcap \\
        gsiftp://localhost:9999/tmp/gridftp.test");
    $output = $u->command("diff /etc/termcap /tmp/gridftp.test");
    $output eq "" ? $u->report("ok") : $u->report("not ok");

    $u->command("rm -f /tmp/gridftp.test");
    $u->command("killall in.ftpd");
}
