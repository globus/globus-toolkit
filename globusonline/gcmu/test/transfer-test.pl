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

use TempUser;

require "transferapi.pl";

my $config_file = "transfer-test.conf";

sub cleanup
{
    my @cmd = ("globus-connect-multiuser-cleanup", "-c", $config_file, "-d",
            "-v");
    my $rc;

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
    return $rc==0;
}

sub gcmu_setup($$)
{
    my $endpoint = shift;
    my $identity_method = shift;
    my @cmd;
    
    $ENV{ENDPOINT_NAME} = $endpoint;
    $ENV{SECURITY_IDENTITY_METHOD} = $identity_method;

    # Create $endpoint
    @cmd = ("globus-connect-multiuser-setup", "-c", $config_file, "-v");
    return system(@cmd) == 0;
}

sub activate_endpoint($$$)
{
    my $endpoint = shift;
    my $username = shift;
    my $password = shift;
    my $json = activate($endpoint, $username, $password);

    return $json->{code} =~ '^Activated\.*' ||
        $json->{code} =~ '^AutoActivated\.*' ||
        $json->{code} =~ '^AlreadyActivated\.*';
}

sub transfer_file($$)
{
    my $endpoint = shift;
    my $user = shift;
    my ($uid, $gid, $home) = ((getpwnam($user))[2,3,7]);
    my $fh;
    my $random_data = "";
    my $copied = "";
    my $res;

    open($fh, ">$home/$endpoint.in");
    $random_data .= chr rand 255 for 1..100;
    $fh->print($random_data);
    $fh->close();
    chown $uid, $gid, "$home/$endpoint.in";

    $res = transfer($endpoint, "$endpoint.in", $endpoint, "$endpoint.out");

    open($fh, "<$home/$endpoint.out");
    read($fh, $copied, length($random_data));
    unlink("$home/$endpoint.in", "$home/$endpoint.out");

    return $copied eq $random_data;
}

sub deactivate_endpoint($)
{
    my $endpoint = shift;
    my $json = deactivate($endpoint);

    return $json->{code} eq 'Deactivated' ||
            $json->{code} eq 'NotActivated';
}

# Prepare
my $random = int(1000000*rand());
my $endpoint = "TRANSFER$random";
my ($random_user, $random_pass) = TempUser->create_user();
if (!$random_user)
{
    exit(1);
}

plan tests => 9;

# Test Step #1:
# Create endpoint with MyProxy authentication
ok(gcmu_setup($endpoint, "MyProxy"), "create_endpoint_myproxy");

# Test Step #2:
# Activate endpoint using MyProxy
ok(activate_endpoint($endpoint, $random_user, $random_pass),
        "activate_with_myproxy");

# Test Step #3:
# Transfer file to myself
ok(transfer_file($endpoint, $random_user), "transfer_file_myproxy");

# Test Step #4:
# Deactivate endpoint
ok(deactivate_endpoint($endpoint), "deactivate_endpoint");

# Test Step #5:
# Update Endpoint with OAuth
ok(gcmu_setup($endpoint, "OAuth"), "create_endpoint_oauth");

# Test Step #6:
# Activate endpoint using OAuth
ok(activate_endpoint($endpoint, $random_user, $random_pass),
        "activate_with_oauth");

# Test Step #7:
# Transfer file to myself
ok(transfer_file($endpoint, $random_user), "transfer_file_oauth");

# Test Step #8:
# Deactivate endpoint
ok(deactivate_endpoint($endpoint), "deactivate_endpoint");

# Test Step #9:
# Clean up
ok(cleanup, "cleanup");
