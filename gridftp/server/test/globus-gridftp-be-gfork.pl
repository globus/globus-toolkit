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
use vars qw(@tests);

my $globus_location = $ENV{GLOBUS_LOCATION};

#$Test::Harness::verbose = 1;

my $nogsi;
my $gfork_pid;
my $gfork_be_pid;

if(defined($nogsi) or defined($ENV{FTP_TEST_NO_GSI}))
{
    $nogsi = 1;
    $ENV{FTP_TEST_NO_GSI} = 1;
    print "Not using GSI security.\n";
}


push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");

&setup_server();
if((0 != system("grid-proxy-info -exists -hours 2 >/dev/null 2>&1") / 256) && !defined($nogsi))
{
    print "Security proxy required to run the tests.\n";
    exit 1;
}

# start registration program
my $done = 0;
$SIG{ALRM} = \&eatfd_db;
alarm 20;


# run tests
print "starting tests\n";

my $rc = system("cd $globus_location/test/globus_ftp_client_test; ./globus-ftp-client-run-tests.pl");

print "tests done\n";
$done = 1;
alarm 0;
&clean_up();
exit $rc;

sub eatfd_db()
{
    my $junk = <SERVER>;
    $junk = <BE_SERVER>;
    if($done == 0)
    {
        $SIG{ALRM} = \&eatfd_db;
        alarm 20;
    }
}

sub clean_up()
{
    print "Cleaning up $gfork_be_pid and $gfork_pid\n";
    if($gfork_be_pid)
    {
        kill(9,-$gfork_be_pid);
        $gfork_be_pid=0;
    }
    if($gfork_pid)
    {
        kill(9,-$gfork_pid);
        $gfork_pid=0;
    }
}

sub setup_server()
{
    my $gfork_prog = "$globus_location/sbin/gfork";
    my $gfork_be_prog = "$globus_location/sbin/gfork";
    my $gfork_be_port;
    my $server_host = "localhost";
    my $server_port = 0;
    my $server_nosec = "";
    my $subject;
    my $use_gsi_opt;
    my $master_gmap;
    my $x;
    my $sec_envs;
    my $server_be_port;

    if(defined($nogsi))
    {
        $server_nosec = "-aa";
    }

    my $gfork_conf = cwd() . "/gfork_conf";
    my $gfork_be_conf = cwd() . "/gfork_be_conf";
    $master_gmap = "$globus_location/test/globus_gridftp_server_test/master_gridmap";
    
    $ENV{GRIDMAP} =  $globus_location . "/test/globus_ftp_client_test/gridmap";

    $sec_envs = "GRIDMAP=$ENV{GRIDMAP}";
    if(!defined($nogsi))
    {
        if(0 != system("grid-proxy-info -exists -hours 2 >/dev/null 2>&1") / 256)
        {
            $ENV{X509_CERT_DIR} = $globus_location . "/test/globus_ftp_client_test";
            $ENV{X509_USER_PROXY} = $globus_location . "/test/globus_ftp_client_test/testcred.pem";
            $sec_envs = "$sec_envs\n  env += X509_CERT_DIR=$ENV{X509_CERT_DIR}";
            $sec_envs = "$sec_envs\n  env += X509_USER_PROXY=$ENV{X509_USER_PROXY}";
            $sec_envs = "$sec_envs\n  env += X509_USER_CERT=$ENV{X509_USER_PROXY}";
        }
   
        my $cmd = "chmod go-rw $globus_location"."/test/globus_ftp_client_test/testcred.pem" ;
        system($cmd);
         
        $subject = `grid-proxy-info -identity`;
        chomp($subject);
        
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

        $use_gsi_opt = "y";
    }
    else
    {
        $use_gsi_opt = "n";
    }


    my $reg_port = 8000 + int(rand(1000));

    # sub in the name for frontend
    open(IN, "<$gfork_conf.in") || die "couldnt open $gfork_conf.in";
    open(OUT, ">$gfork_conf") || die "couldnt open $gfork_conf";
    $x = join('', <IN>);
    $x =~ s/\@GLOBUS_LOCATION@/$globus_location/g;
    $x =~ s/\@GSI@/$use_gsi_opt/g;
    $x =~ s/\@REG_PORT@/$reg_port/g;
    $x =~ s/\@SEC_ENVS@/$sec_envs/g;
    print OUT $x;
    close(IN);
    close(OUT);

    print "starting $gfork_prog -c $gfork_conf\n";
    $gfork_pid = open(SERVER, "$gfork_prog -c $gfork_conf |");
    if($gfork_pid == -1)
    {
        print "Unable to start server\n";
        exit 1;
    }
    select((select(SERVER), $| = 1)[0]);
    $server_port = <SERVER>;
    my $fe_cs = $server_port;
    $fe_cs =~ s/Listening on: //;
    $server_port =~ s/Listening on: .*?:(\d+)/\1/;
    chomp($server_port);
    if($server_port !~ /\d+/)
    {
        print "Unable to start server\n";
        exit 1;
    }
    print "Started gfork on port $server_port\n";

    # sub in the name for frontend

    $fe_cs = "localhost:$reg_port";
    open(IN, "<$gfork_be_conf.in") || die "couldnt open $gfork_be_conf.in";
    open(OUT, ">$gfork_be_conf") || die "couldnt open $gfork_be_conf";
    $x = join('', <IN>);
    $x =~ s/\@GLOBUS_LOCATION@/$globus_location/g;
    $x =~ s/\@GSI@/$use_gsi_opt/g;
    $x =~ s/\@SEC_ENVS@/$sec_envs/g;
    $x =~ s/\@FE_CS@/$fe_cs/g;
    print OUT $x;
    close(IN);
    close(OUT);

    sleep 15;

    print "starting $gfork_be_prog -c $gfork_be_conf\n";
    $gfork_be_pid = open(BE_SERVER, "$gfork_be_prog -c $gfork_be_conf |");
    if($gfork_be_pid == -1)
    {
        print "Unable to start server\n";
        exit 1;
    }
    select((select(BE_SERVER), $| = 1)[0]);
    $server_be_port = <BE_SERVER>;
    $server_be_port =~ s/Listening on: .*?:(\d+)/\1/;
    chomp($server_be_port);
    if($server_be_port !~ /\d+/)
    {
        print "Unable to start server\n";
        exit 1;
    }
    print "Started gfork backend on port $server_be_port\n";


    # sleep a second, some hosts are slow....

    $ENV{GLOBUS_FTP_CLIENT_TEST_SUBJECT} = $subject;
    $ENV{FTP_TEST_SOURCE_HOST} = "$server_host:$server_port";
    $ENV{FTP_TEST_DEST_HOST} = "$server_host:$server_port";   

    sleep 5;
    
    return;
}

