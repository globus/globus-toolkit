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

END {$?=0}

# This test runs gcmu setup twice on the same config file. It should end
# with the same config after the second run as after the first one

use strict;
use File::Path;
use Test::More;

require "transferapi.pl";

plan tests => 5;

# Prepare
my $random = int(1000000*rand());
my $endpoint = "DOUBLE$random";
my $server = "DOUBLE$random";
my $base_url = "https://transfer.api.globusonline.org/v0.10";
my $config_file = "test-reset.conf";

# Test Step #1:
# Create endpoint
ok(gcmu_setup($endpoint, $server) == 0, "create_endpoint");

# Test Step #2:
# Get number of servers on endpoint, assert == 1
ok(count_servers($endpoint) == 1, "count_servers1");

# Test Step #3:
# Update endpoint with the same server
ok(gcmu_setup($endpoint, $server) == 0, "update_endpoint1");

# Test Step #4:
# Get number of servers on endpoint, assert == 1
ok(count_servers($endpoint) == 1, "count_servers2");

# Test Step #5:
# Clean up gcmu
ok(cleanup() == 0, "cleanup");

sub count_servers($$$)
{
    my $endpoint = shift;
    my $json = get_endpoint($endpoint);

    return scalar(map($_->{hostname}, @{$json->{DATA}}));
}

sub cleanup
{
    my @cmd;
    my $rc;

    $cmd[0] = "globus-connect-multiuser-cleanup";
    $cmd[1] = "-c";
    $cmd[1] = $config_file;
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
    return $rc;
}

sub gcmu_setup($$;@)
{
    my $endpoint = shift;
    my $server = shift;
    my @other_options = @_;
    my @cmd;
    my $rc;
    
    $ENV{RANDOM_ENDPOINT} = $endpoint;
    $ENV{RANDOM_SERVER} = $server;

    # Create $endpoint
    @cmd = ("globus-connect-multiuser-setup", "-c", $config_file, @other_options);
    return system(@cmd);
}
