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
    my $source_port;
    my $dest_port;

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
        $u->command_blocking("in.ftpd -a -1 -s -p 0");
    
    $_ = `ps -p $source_pid -o args`;
    s/ftpd: accepting connections on port (\d+)/\1/;
    $source_port = $1;

    my ($dest_pid, $dest_fd) = 
        $u->command_blocking("in.ftpd -a -1 -s -p 0");

    $_ = `ps -p $dest_pid -o args`;
    s/ftpd: accepting connections on port (\d+)/\1/;
    $dest_port = $1;

    sleep 1;

    my $tmpfile = POSIX::tmpnam();

    ($rc, $output) = $u->command("globus-url-copy -s \"$subject\" \\
        gsiftp://localhost:$source_port/etc/group \\
        gsiftp://localhost:$dest_port$tmpfile 2>&1",5);

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

    $output .= ($u->command("diff /etc/group $tmpfile"))[1];
    $output eq "" ? $u->report("SUCCESS") : $u->report("FAILURE");

    $u->command("rm -f $tmpfile");
}
