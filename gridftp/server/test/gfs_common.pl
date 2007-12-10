#! /usr/bin/env perl

# 
# Copyright 1999-2006 University of Chicago
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 


use strict;
use Test::Harness;
use Cwd;
use Getopt::Long;
require 5.005;

my $globus_location = $ENV{GLOBUS_LOCATION};
my $server_prog = "$globus_location/sbin/globus-gridftp-server";
my @cleanup_pids;
my $gfs_working_dir=$ENV{GLOBUS_LOCATION}."/test/globus_gridftp_server_test";
my $gfs_subject;

#$Test::Harness::verbose = 1;

sub gfs_cleanup()
{
    my $pid;

    while($#cleanup_pids)
    {
        $pid = pop(@cleanup_pids);
        kill(-9, $_);
    }
}

# run the server in basic mode
sub gfs_setup_server_basic()
{
    my $server_pid;
    my $server_port;
    my $server_host = "localhost";
    my $server_args = "";
    my $subject;

    if($ENV{FTP_TEST_NO_GSI} == 1)
    {
        $server_args = " -aa ";
    }

    my $server_args = "-no-fork -no-chdir -d 0 ".$server_args;
    
    $server_pid = open(SERVER, "$server_prog $server_args |");
    if($server_pid == -1)
    {
        print "Unable to start server\n";
        exit 1;
    }

    select((select(SERVER), $| = 1)[0]);
    $server_port = <SERVER>;
    $server_port =~ s/Server listening at //;
    chomp($server_port);

    if($server_port !~ /\d+/)
    {
        print "Unable to start server\n";
        exit 1;
    }
    
    print "Started server at port $server_port\n";

    $ENV{GLOBUS_FTP_CLIENT_TEST_SUBJECT} = $subject;
    $ENV{FTP_TEST_SOURCE_HOST} = "$server_host:$server_port";
    $ENV{FTP_TEST_DEST_HOST} = "$server_host:$server_port";   

    sleep 1;

    push(@cleanup_pids, $server_pid);

    return $server_pid, $server_port;
}

sub gfs_setup_security_env()
{
    my $subject;

    if($ENV{FTP_TEST_NO_GSI} == 1)
    {
        return;
    }

    if(0 != system("grid-proxy-info -exists -hours 2 >/dev/null 2>&1") / 256)
    {
        $ENV{X509_CERT_DIR} = $gfs_working_dir;
        $ENV{X509_USER_PROXY} = $gfs_working_dir . "/testcred.pem";

        my $cmd = "chmod 600 $ENV{X509_USER_PROXY}";
        system($cmd);
    }

    system('chmod go-rw testcred.pem');

    $subject = `grid-proxy-info -identity`;
    chomp($subject);
    $gfs_subject = $subject;
    $ENV{GLOBUS_FTP_CLIENT_TEST_SUBJECT} = $subject;

    $ENV{GRIDMAP} = $gfs_working_dir . "/gridmap";
    if ( -f $ENV{GRIDMAP})
    {
        system('mv $GRIDMAP $GRIDMAP.old');
    }
    if( 0 != system("grid-mapfile-add-entry -dn \"$subject\" -ln `whoami` -f $ENV{GRIDMAP} >/dev/null 2>&1") / 256)
    {
        print "Unable to create gridmap file\n";
        exit 1;
    }

    return $subject;
}

sub gfs_setup_server_fe()
{
    my $gfork_prog = "$globus_location/sbin/gfork";
    my $gfork_pid;
    my $server_host = "localhost";
    my $server_port = 0;
    my $server_nosec = "";
    my $subject;
    my $use_gsi_opt; 
    my $master_gmap;
    my $x;
    my $sec_envs;
    my $use_gsi_opt;
    my $register_args;
    
    if($ENV{FTP_TEST_NO_GSI} == 1)
    {
        $server_nosec = "-aa";
    }

    my $gfork_single_conf = $gfs_working_dir . "/gfork_single_conf";
    $master_gmap = $ENV{GRIDMAP};

    $sec_envs = "GRIDMAP=$ENV{GRIDMAP}";
    if($ENV{FTP_TEST_NO_GSI} == 1)
    {
        $sec_envs = "$sec_envs\n  env += X509_CERT_DIR=$ENV{X509_CERT_DIR}";
        $sec_envs = "$sec_envs\n  env += X509_USER_PROXY=$ENV{X509_USER_PROXY}";
        $sec_envs = "$sec_envs\n  env += X509_USER_CERT=$ENV{X509_USER_PROXY}";

        $subject = $gfs_subject;

        $use_gsi_opt = "y";
        $register_args = "-q -G y";
    }
    else
    {
        $register_args = "-q -G n";
        $use_gsi_opt = "n";
    }


    open(IN, "<$gfork_single_conf.in") || die "couldnt open $gfork_single_conf.in";
    open(OUT, ">$gfork_single_conf") || die "couldnt open $gfork_single_conf";
    $x = join('', <IN>);
    $x =~ s/\@GLOBUS_LOCATION@/$globus_location/g;
    $x =~ s/\@GSI@/$use_gsi_opt/g;
    $x =~ s/\@SEC_ENVS@/$sec_envs/g;
    print OUT $x;
    close(IN);
    close(OUT);

    print "starting $gfork_prog -c $gfork_single_conf\n";
    $gfork_pid = open(SERVER, "$gfork_prog -c $gfork_single_conf |");
    if($gfork_pid == -1)
    {
        print "Unable to start server\n";
        exit 1;
    }
    select((select(SERVER), $| = 1)[0]);
    $server_port = <SERVER>;
    $server_port =~ s/Listening on: //;
    chomp($server_port);
    print "Started gfork on port $server_port\n";


    sleep 1;
    push(@cleanup_pids, $gfork_pid);

    return $gfork_pid,$server_port;
}

1;
