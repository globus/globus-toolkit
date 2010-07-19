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
use CGI;
use File::Temp;

my @commands;
my @replies;
my $server_port;
my $server_pid;
my $backend_pid;

$commands[0] = "USER test";             $replies[0] = "331";
$commands[1] = "PASS test";             $replies[1] = "230";
$commands[2] = "PWD";                   $replies[2] = "257";
$commands[3] = "STAT";                  $replies[3] = "212";
$commands[4] = "STAT ~";                $replies[4] = "213";
$commands[5] = "MKD tEstT";             $replies[5] = "257";
$commands[6] = "CWD tEstT";             $replies[6] = "250";
$commands[7] = "CDUP";                  $replies[7] = "250";
$commands[8] = "RMD tEstT";             $replies[8] = "250";
$commands[9] = "SITE DSI file";         $replies[9] = "250";
$commands[10] = "SITE DSI remote";      $replies[10] = "500";
$commands[11] = "SITE DSI bAd";         $replies[11] = "500";
$commands[12] = "QUIT";                 $replies[12] = "221";

my $server_exe="$ENV{'GLOBUS_LOCATION'}/sbin/globus-gridftp-server";
my $client_exe="./xio-ftp";

my $cmd_file=mktemp("/tmp/cmd_tmpfileXXXXX");
open(CMD_FILE, ">$cmd_file") || die "couldn't open command file";
foreach(@commands)
{
    print CMD_FILE "$_\n";
}
close(CMD_FILE);


# make the password file
my $pw_file=mktemp("/tmp/pw_tmpfileXXXXX");
system("./gfs-addpw.sh $pw_file test test");

my $ctr;
for($ctr = 0; $ctr < 2; $ctr++)
{
    &run_client("-nf", $ctr);
    &run_client("-d 255", $ctr);
    &run_client("-fork", $ctr);
}

unlink("$pw_file");
unlink("$cmd_file");

sub run_client
{
    my $otha_args=shift;
    my $be = shift;

    $server_pid =
        &run_server("$otha_args -debug -password-file $pw_file", $be);

    open(CLIENT, "$client_exe localhost:$server_port < $cmd_file  |");
    my $server_reply=<CLIENT>;
    if(!($server_reply =~ m/^220/))
    {
        print "ERROR: no 220: $server_reply\n";
        exit 1;
    }

    my $ndx = 0;
    while($server_reply=<CLIENT>)
    {
        if(!($server_reply =~ m/^$replies[$ndx]/))
        {
            print "ERROR: $ndx $replies[$ndx] :: $server_reply\n";
            exit 1;
        }
        $ndx++;
    }

    kill(2,$server_pid);

    if($be == 1)
    {
        kill(2,$backend_pid);
    }
    print "===== success ==== \n";
}

sub run_server
{
    my $backend_port;
    my $server_args = shift;
    my $run_backend = shift;
    my $pid;

    if($run_backend == 1)
    {
        print "RUNNING BACKEND\n";
        my $backend_args = "-no-fork -no-chdir -dn -d 0 -debug -password-file $pw_file";
        $backend_pid = open(BACKEND, "$server_exe $backend_args |");
        if($backend_pid == -1)
        {
            print "Unable to start server\n";
            exit 1;
        }

        print "$server_exe $backend_args\n";
        select((select(BACKEND), $| = 1)[0]);
        $backend_port = <BACKEND>;
        $backend_port =~ s/Server listening at .*?:(\d+)/\1/;
        chomp($backend_port);
        if($backend_port !~ /\d+/)
        {
            print "Unable to start server\n";
            exit 1;
        }
        $server_args = "$server_args -r localhost:$backend_port";
    }

    print "$server_exe $server_args\n";
    $pid = open(SERVER, "$server_exe $server_args |");
    if($pid == -1)
    {
        print "Unable to start server\n";
        exit 1;
    }
    select((select(SERVER), $| = 1)[0]);
    $server_port = <SERVER>;
    $server_port =~ s/Server listening at .*?:(\d+)/\1/;
    chomp($server_port);
    if($server_port !~ /\d+/)
    {
        print "Unable to start server\n";
        exit 1;
    }

    return $pid;
}
