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

require "transferapi.pl";

my $config_file = "multi-node-test.conf";

sub count_servers($)
{
    my $json = get_endpoint($_[0]);

    return scalar(map($_->{hostname}, @{$json->{DATA}}));
}

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
plan tests => 3;

my $random = int(1000000*rand());
my $endpoint = "MULTI$random";
my $base_url = "https://transfer.api.globusonline.org/v0.10";
my $test_mode;
my $hostname = (POSIX::uname())[1];

if (! exists $ENV{MYPROXY_SERVER})
{
    $test_mode = "all-services-local";
    $ENV{MYPROXY_SERVER} = $ENV{OAUTH_SERVER} = $ENV{GRIDFTP_SERVER} = 
            $hostname;
}
elsif (! exists $ENV{OAUTH_SERVER})
{
    $ENV{OAUTH_SERVER} = $ENV{GRIDFTP_SERVER} = $hostname;
    $test_mode = "remote-myproxy";
}
else
{
    $test_mode = "remote-myproxy-and-oauth";
    $ENV{GRIDFTP_SERVER} = $hostname;
}

# Test Step #1:
# Create endpoint
ok(gcmu_setup($endpoint), "$test_mode:create_endpoint");

# Test Step #2:
# Get number of servers on endpoint, assert == 1
ok(count_servers($endpoint) == 1, "$test_mode:count_servers1");

# Test Step #3:
# Clean up gcmu
ok(cleanup(), "$test_mode:cleanup");
