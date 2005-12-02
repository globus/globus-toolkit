#!/usr/bin/env perl

#
# Portions of this file Copyright 1999-2005 University of Chicago
# Portions of this file Copyright 1999-2005 The University of Southern California.
#
# This file or a portion of this file is licensed under the
# terms of the Globus Toolkit Public License, found at
# http://www.globus.org/toolkit/download/license.html.
# If you redistribute this file, with or without
# modifications, you must include this notice in the file.
#


BEGIN { push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl"); }

# ------------------------------------------------------------------------
# globus_test_gridftp_local
# ------------------------------------------------------------------------

use strict;
use Globus::Testing::Utilities;
use POSIX;

test_gridftp_local();


# ------------------------------------------------------------------------
# Test GridFTP local
# ------------------------------------------------------------------------
sub test_gridftp_local 
{
    my $u = new Utilities();
    my $output;
    my $rc;
    my $source_port;
    my $dest_port;

    $u->announce("Testing GridFTP locally");

    my $subject = `grid-proxy-info -identity`;
    chomp($subject);
    
    my $gridmap=`pwd`;
    chomp $gridmap;
    $ENV{GRIDMAP}="$gridmap/gridmap";

    if(! -f $ENV{GRIDMAP})
    {
        if( 0 != system("grid-mapfile-add-entry -dn \"$subject\" -ln `whoami` -f $ENV{GRIDMAP} >/dev/null 2>&1") / 256)
        {
            print "Unable to create gridmap file\n";
            exit 1;
        }
    }
    
    my ($source_pid, $source_fd) = 
        $u->command_blocking("globus-gridftp-server -1 -s -p 0");
    
    my ($dest_pid, $dest_fd) = 
        $u->command_blocking("globus-gridftp-server -1 -s -p 0");

    select((select($source_fd), $| = 1)[0]);
    $source_port = <$source_fd>;
    $source_port =~ s/Server listening at \S+:(\d+)/\1/;
    chomp($source_port);

    select((select($dest_fd), $| = 1)[0]);
    $dest_port = <$dest_fd>;
    $dest_port =~ s/Server listening at \S+:+(\d+)/\1/;
    chomp($dest_port);

    sleep 1;

    my $tmpfile = POSIX::tmpnam();

    ($rc, $output) = $u->command("globus-url-copy -s \"$subject\" \\
        gsiftp://localhost:$source_port/etc/group \\
        gsiftp://localhost:$dest_port$tmpfile 2>&1",5);

    if($rc != 0)
    {
        if ($source_pid > 0 && $dest_pid > 0) {
           kill(9, $source_pid, $dest_pid); 
        }
    }

    my ($server_rc, $server_output) = $u->wait_command($source_pid,
                                                       $source_fd);
    
    if($server_rc != 0)
    {
        $output .= "$server_output\n";
    }

    ($server_rc, $server_output) = $u->wait_command($dest_pid,
                                                    $dest_fd);

    if($server_rc != 0)
    {
        $output .= "$server_output\n";
    }

    $output .= ($u->command("diff /etc/group $tmpfile"))[1];
    $output eq "" ? $u->report("SUCCESS") : $u->report("FAILURE");

    $u->command("rm -f $tmpfile");
}
