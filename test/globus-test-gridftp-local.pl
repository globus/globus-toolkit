#!/usr/bin/env perl

# ------------------------------------------------------------------------
# globus_test_gridftp_local
# ------------------------------------------------------------------------

use strict;
use Utilities;
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

    $u->announce("Testing GridFTP locally");

    my $subject = `grid-proxy-info -subject`;
    chomp($subject);

    $subject =~ s|(/CN=proxy)*||g;
    
    $ENV{GRIDMAP}="gridmap";
    
    if( 0 != system("grid-mapfile-add-entry -dn \"$subject\" -ln `whoami` -f $ENV{GRIDMAP} >/dev/null 2>&1") / 256)
    {
        print "Unable to create gridmap file\n";
        exit 1;
    }

    my ($source_pid, $source_fd) = 
        $u->command_blocking("in.ftpd -a -1 -s -p 9999");
    my ($dest_pid, $dest_fd) = 
        $u->command_blocking("in.ftpd -a -1 -s -p 9998");

    sleep 1;

    my $tmpfile = POSIX::tmpnam();

    ($rc, $output) = $u->command("globus-url-copy -s \"$subject\" \\
        gsiftp://localhost:9998/etc/group \\
        gsiftp://localhost:9999$tmpfile 2>&1");

    if($rc != 0)
    {
        kill(9, $source_pid, $dest_pid); 
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

    $output .= ($u->command("diff /etc/group $tmpfile",1))[1];
    $output eq "" ? $u->report("SUCCESS") : $u->report("FAILURE");

    $u->command("rm -f $tmpfile");
}
