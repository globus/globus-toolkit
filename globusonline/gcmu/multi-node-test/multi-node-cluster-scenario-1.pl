#! /usr/bin/perl
#
# Copyright 1999-2013 University of Chicago
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

# Scenario #1:
# Multiple File Servers and a Shared Identity Provider in a Cluster

BEGIN
{
    $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = "0";
}

END {$?=0}

use strict;
use File::Path;
use POSIX;
use LWP;
use URI::Escape;
use Test::More;

require "barrier.pl";

my $config_file = "multi-node-cluster-scenario-1.conf";

sub cleanup()
{
    my @cmd;
    my $rc;

    $cmd[0] = "globus-connect-multiuser-cleanup";
    $cmd[1] = "-c";
    $cmd[2] = $config_file;
    $cmd[3] = "-d";
    $rc = system(@cmd);

    # Just to make sure that doesn't fail
    foreach my $f (</etc/gridftp.d/globus-connect*>)
    {
        unlink($f);
    }
    foreach my $f (</etc/myproxy.d/globus-connect*>)
    {
        unlink($f);
    }
    File::Path::rmtree("/var/lib/globus-connect-multiuser");
    unlink("/var/lib/myproxy-oauth/myproxy-oauth.db");
    return $rc == 0;
}

sub gcmu_setup($;@)
{
    my $endpoint = shift;
    my @other_options = @_;
    my @cmd;
    my $rc;
    
    $ENV{ENDPOINT} = $endpoint;

    # Create $endpoint
    @cmd = ("globus-connect-multiuser-setup", "-c", $config_file, @other_options);
    return system(@cmd)==0;
}


# Prepare
my $random = int(1000000*rand());
my $endpoint = "MULTI$random";
my $test_mode;
my $hostname;

if ($ENV{PUBLIC_HOSTNAME}) {
    $hostname = $ENV{PUBLIC_HOSTNAME};
} else {
    $hostname = (POSIX::uname())[1];
}


set_barrier_prefix("multi-node-cluster-scenario-1-");

my $res = barrier(1, hostname=>$hostname);

# Determine our rank in the list of machines from the first barrier
my $rank = rank(%{$res});

$ENV{ID_NODE} = $res->[0]->{hostname};
$ENV{WEB_NODE} = $res->[0]->{hostname};
$ENV{IO_NODE} = $hostname;

# Test step #1:
# Create ID, I/O and Web server on node 0
if ($rank == 0)
{
    ok(gcmu_setup($endpoint), "setup_id_web_io");
}
else
{
    ok(1, "setup_id_web_io_noop");
}

# barrier to wait for id/web node to configure
$res = barrier(2, rank=>$rank);

# Test step #2:
# Create I/ servers on other nodes
if ($rank == 0)
{
    ok(1, "setup_io_noop");
}
else
{
    ok(gcmu_setup($endpoint), "setup_io");
}

# barrier to wait for I/O node to configure
$res = barrier(3, rank=>$rank, endpoint=>$endpoint);

# Test Step #4:
TODO: {
    todo_skip "Transfer Tests Not Implemented", 1 if 1;
    ok(transfer_between_nodes(), "transfer_between_nodes");
} 

# barrier to wait for transfer tests to complete
$res = barrier(4, rank=>$rank);

# Test Step #5:
# Clean up gcmu
ok(cleanup(), "cleanup");
