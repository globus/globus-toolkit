#!/usr/bin/env perl

BEGIN { push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl"); }

# ------------------------------------------------------------------------
# globus_test_gridftp_remote
# ------------------------------------------------------------------------

use POSIX;
use strict;
use Globus::Testing::Utilities;

if ($ENV{'TEST_REMOTE'}) 
{
    test_gridftp_remote();
}

# ------------------------------------------------------------------------
# Test GridFTP remote
# ------------------------------------------------------------------------
sub test_gridftp_remote 
{
    my $u = new Utilities();
    $u->announce("Testing GridFTP remotely");

    my $output;
    my $remote = $u->remote;
    my $hostname = $u->hostname;
    my $tmpfile = POSIX::tmpnam();
    my $rc;

    $rc = $u->command("globus-url-copy \\
        gsiftp://$remote/etc/group \\
        gsiftp://$hostname$tmpfile",5);
    $rc == 0 ? $u->report("SUCCESS") : $u->report("FAILURE");

    $u->command("rm -f $tmpfile");
}
