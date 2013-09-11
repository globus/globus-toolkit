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
use IPC::Open3;
use Test::More;

use TempUser;
use GlobusTransferAPIClient;

my $api = GlobusTransferAPIClient->new();

my $config_file = "activation-test.conf";

sub diagsystem(@)
{
    my @cmd = @_;
    my ($pid, $in, $out, $err);
    my ($outdata, $errdata);
    $pid = open3($in, $out, $err, @cmd);
    close($in);
    local($/);
    $outdata = <$out>;
    $errdata = <$err>;
    diag("$cmd[0] stdout: $outdata") if ($outdata);
    diag("$cmd[0] stderr: $errdata") if ($errdata);
    waitpid($pid, 0);
    return $?;
}

sub cleanup
{
    my @cmd = ("globus-connect-multiuser-cleanup", "-c", $config_file, "-d",
            "-v");
    my $rc = diagsystem(@cmd);

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
    my @cmd = ("globus-connect-multiuser-setup", "-c", $config_file, "-v");
    
    $ENV{ENDPOINT_NAME} = $endpoint;
    $ENV{SECURITY_IDENTITY_METHOD} = $identity_method;

    my $rc = diagsystem(@cmd);
    return $rc == 0;
}

sub activate_endpoint($$$)
{
    my $endpoint = shift;
    my $username = shift;
    my $password = shift;
    my $json = $api->activate($endpoint, $username, $password);

    return $json->{code} =~ '^Activated\.*' ||
        $json->{code} =~ '^AutoActivated\.*' ||
        $json->{code} =~ '^AlreadyActivated\.*';
}

sub deactivate_endpoint($)
{
    my $endpoint = shift;
    my $json = $api->deactivate($endpoint);

    return $json->{code} eq 'Deactivated' ||
            $json->{code} eq 'NotActivated';
}

# Prepare
my $random = int(1000000*rand());
my $endpoint = "ACTIVATE$random";
my ($random_user, $random_pass) = TempUser::create_user();
if (!$random_user)
{
    exit(1);
}

plan tests => 7;

# Test Step #1:
# Create endpoint with MyProxy authentication
ok(gcmu_setup($endpoint, "MyProxy"), "create_endpoint_myproxy");

# Test Step #2:
# Activate endpoint using MyProxy
ok(activate_endpoint($endpoint, $random_user, $random_pass),
        "activate_with_myproxy");

# Test Step #3:
# Deactivate endpoint
ok(deactivate_endpoint($endpoint), "deactivate_endpoint");

# Test Step #4:
# Update Endpoint with OAuth
ok(gcmu_setup($endpoint, "OAuth"), "create_endpoint_oauth");

# Test Step #5:
# Activate endpoint using OAuth
ok(activate_endpoint($endpoint, $random_user, $random_pass),
        "activate_with_oauth");

# Test Step #6:
# Deactivate endpoint
ok(deactivate_endpoint($endpoint), "deactivate_endpoint");


# Test Step #7:
# Clean up
ok(cleanup, "cleanup");
