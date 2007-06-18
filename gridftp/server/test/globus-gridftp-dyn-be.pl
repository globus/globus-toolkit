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
use FtpTestLib;
require 5.005;
use vars qw(@tests);

my $globus_location = $ENV{GLOBUS_LOCATION};

#$Test::Harness::verbose = 1;

my $nogsi;
my $register_args;
my $be_pid;
my $gfork_pid;

if(defined($nogsi) or defined($ENV{FTP_TEST_NO_GSI}))
{
    $nogsi = 1;
    $ENV{FTP_TEST_NO_GSI} = 1;
    print "Not using GSI security.\n";
}

if((0 != system("grid-proxy-info -exists -hours 2 >/dev/null 2>&1") / 256) && !defined($nogsi))
{
    print "Security proxy required to run the tests.\n";
    exit 1;
}

push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");

&setup_server();

# start registration program
print "registering be\n";
&register_db();
$SIG{ALRM} = sub { $register_db };
alarm 30;

# run tests
print "starting tests\n";

my $rc = system("$globus_location/test/globus_ftp_client_test/globus-ftp-client-run-tests.pl");

exit $rc;

sub clean_up()
{
    if($be_pid)
    {
        kill(9,$be_pid);
        $be_pid=0;
    }
    if($gfork_pid)
    {
        kill(9,$gfork_pid);
        $gfork_pid=0;
    }
}


sub register_db()
{
    my $rc;

    $rc = $globus_location/libexec/gfs-dynbe-client $register_args / 256;

    if($rc != 0)
    {
        print "Failed to register backend\n";
        &clean_up();
        exit 1;
    }
}

sub setup_server()
{
    my $gfork_prog = "$globus_location/sbin/gfork";
    my $be_prog = "$globus_location/sbin/globus-gridftp-server";
    my $be_args = "-dn -aa";
    my $server_host = "localhost";
    my $server_port = 0;
    my $server_nosec = "";
    my $subject;
    my $use_gsi_opt;
    my $master_gmap;
    if(defined($nogsi))
    {
        $server_nosec = "-aa";
    }

    my $gfork_conf = cwd() . "/gfork_conf";
    $master_gmap = "$globus_location/test/globus_gridftp_server_test/master_gridmap";
    
    if(!defined($nogsi))
    {
        if(0 != system("grid-proxy-info -exists -hours 2 >/dev/null 2>&1") / 256)
        {
            $ENV{X509_CERT_DIR} = $globus_location . "test/globus_ftp_client_test";
            $ENV{X509_USER_PROXY} = $globus_location . "test/globus_ftp_client_test/testcred.pem";
        }
    
        system('chmod go-rw testcred.pem');
         
        $subject = `grid-proxy-info -identity`;
        chomp($subject);
        
        $ENV{GRIDMAP} =  $globus_location . "test/globus_ftp_client_test/gridmap";
        if ( -f $ENV{GRIDMAP})
        {
            system('mv $GRIDMAP $GRIDMAP.old');    
        }   
        if( 0 != system("grid-mapfile-add-entry -dn \"$subject\" -ln `whoami` -f $ENV{GRIDMAP} >/dev/null 2>&1") / 256)
        {
            print "Unable to create gridmap file\n";
            exit 1;
        }

        if( 0 != system("cp $ENV{GRIDMAP} $master_gmap") / 256)
        {
            print "Unable to create master gridmap file\n";
            exit 1;
        }

        $use_gsi_opt = " y ";
        $register_args = " -G y ";
    }
    else
    {
        $register_args = " -G n ";
        $use_gsi_opt = " n ";
    }

    $gfork_pid = open(SERVER, "$gfork_prog -c $gfork_conf |");
    if($gfork_pid == -1)
    {
        print "Unable to start server\n";
        exit 1;
    }
    select((select(SERVER), $| = 1)[0]);
    $server_port = <SERVER>;
    $server_port =~ s/Listening on .*?:(\d+)/\1/;
    chomp($server_port);
    if($server_port !~ /\d+/)
    {
        print "Unable to start server\n";
        exit 1;
    }
    print "Started gfork on port $server_port\n";

    $be_pid = open(BE_SERVER, "$be_prog $be_args |");
    if($be_pid == -1)
    {
        print "Unable to start server\n";
        exit 1;
    }
    select((select(BE_SERVER), $| = 1)[0]);
    $be_port = <BE_SERVER>;
    $be_port =~ s/Server listening at .*?:(\d+)/\1/;
    chomp($be_port);
    if($be_port !~ /\d+/)
    {
        print "Unable to start server\n";
        exit 1;
    }
    print "Started backend on port $be_port\n";

    # sleep a second, some hosts are slow....

    # sub in the files
    open(IN, "<$gfork_conf.in");
    open(OUT, ">$gfork_conf");
    $x = join('', <IN>);
    $x =~ s/"\@GLOBUS_LOCATION@"/$globus_location/g;
    $x =~ s/"\@GSI@"/$use_gsi_opt/g;
    print OUT $x;
    close(IN);
    close(OUT);

    sleep 5;
    
    $ENV{GLOBUS_FTP_CLIENT_TEST_SUBJECT} = $subject;
    $ENV{FTP_TEST_SOURCE_HOST} = "$server_host:$server_port";
    $ENV{FTP_TEST_DEST_HOST} = "$server_host:$server_port";   

    $register_args = $register_args . "localhost:$be_port localhost:6065";

    return;
}

