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

my $config_file = "activation-test.conf";

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

sub gcmu_setup($;@)
{
    my $endpoint = shift;
    my @other_options = @_;
    my @cmd;
    
    $ENV{ENDPOINT_NAME} = $endpoint;

    # Create $endpoint
    @cmd = ("globus-connect-multiuser-setup", "-c", $config_file, "-v", @other_options);
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

sub deactivate_endpoint($)
{
    my $endpoint = shift;
    my $json = deactivate($endpoint);

    return $json->{code} eq 'Deactivated' ||
            $json->{code} eq 'NotActivated';
}


# Prepare
my $random = int(1000000*rand());
my $endpoint = "ACTIVATE$random";
my @chars = ("a".."z");
my @nums = ("0".."9");
my @pwchars = ("A".."Z", "a".."z", "0".."9", "^","&","*","(",")",",",".");

my $random_user="";
my $random_pass="";
my $salt = "";
my $crypted;
$random_user .= $chars[rand @chars] for 1..8;
$random_user .= $nums[rand @nums] for 1..3;
$random_pass .= $pwchars[rand @pwchars] for 1..12;
$salt .= $chars[rand @chars] for 1..2;
$crypted = crypt($random_pass, $salt);
system("useradd $random_user -p \"$crypted\"") == 0 || die "Error creating test user";
END { if ($random_user) { system("userdel \"$random_user\""); } }

plan tests => 4;

# Test Step #1:
# Create endpoint
ok(gcmu_setup($endpoint), "create_endpoint");

# Test Step #2:
# Activate endpoint using MyProxy
ok(activate_endpoint($endpoint, $random_user, $random_pass),
        "activate_endpoint");

# Test Step #3:
# Deactivate endpoint
ok(deactivate_endpoint($endpoint), "deactivate_endpoint");

# Test Step #4:
# Clean up
ok(cleanup(), "cleanup");
