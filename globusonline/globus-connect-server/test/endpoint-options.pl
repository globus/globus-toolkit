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

use strict;
use File::Path;
use File::Temp;
use IPC::Open3;
use Test::More;
use GlobusTransferAPIClient;

my $api = GlobusTransferAPIClient->new();

my $config_file = "endpoint-options.conf";

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

sub setup_server($$$)
{
    my ($endpoint_name, $endpoint_public, $default_dir) = @_;
    my @cmd = ("globus-connect-server-setup", "-c", $config_file);

    $ENV{ENDPOINT_NAME} = $endpoint_name;
    $ENV{ENDPOINT_PUBLIC} = $endpoint_public;
    $ENV{ENDPOINT_DIR} = $default_dir;

    my $rc = diagsystem(@cmd);
    return $rc == 0;
}

sub is_endpoint_public($)
{
    my $endpoint = shift;
    my $json;

    $json = $api->get_endpoint($endpoint);

    return $json->{public};
}

sub is_default_dir($$)
{
    my ($endpoint, $dir) = @_;
    my $json;

    $json = $api->get_endpoint($endpoint);

    return $json->{default_directory} eq $dir;
}

sub cleanup($)
{
    my $endpoint_name = shift;
    my @cmd = ("globus-connect-server-cleanup", "-c", $config_file, "-d");

    $ENV{ENDPOINT_NAME} = $endpoint_name;
    $ENV{ENDPOINT_PUBLIC} = "False";
    $ENV{ENDPOINT_DIR} = "/~/";

    my $rc = diagsystem(@cmd);
    return $rc == 0;
}

sub force_cleanup()
{
    # Just to make sure that doesn't fail
    foreach my $f (</etc/gridftp.d/globus-connect*>)
    {
        unlink($f);
    }
    foreach my $f (</etc/myproxy.d/globus-connect*>)
    {
        unlink($f);
    }
    File::Path::rmtree("/var/lib/globus-connect-server");
    unlink("/var/lib/myproxy-oauth/myproxy-oauth.db");
}

# Prepare
plan tests => 12;
my $random = int(1000000*rand());
my $endpoint_name = "ENDPOINT_OPTIONS_$random";

# Test Step #1:
# Setup server with (Public=True, DefaultDirectory="/tmp")
ok(setup_server($endpoint_name, 1, "/tmp"), "setup_server_public_tmp");

# Test Step #2:
# Check that endpoint's Public attribute is True
ok(is_endpoint_public($endpoint_name), "is_endpoint_public");

# Test Step #3:
# Check that endpoint's DefaultDirectory attribute is /tmp
ok(is_default_dir($endpoint_name, "/tmp"), "is_default_dir_tmp");

# Test Step #4
# Set up server with (Public=False, DefaultDirectory="/tmp")
ok(setup_server($endpoint_name, 0, "/tmp"), "setup_server_non_public_tmp");

# Test Step #5:
# Check that endpoint's Public attribute is False
ok(!is_endpoint_public($endpoint_name), "is_endpoint_non_public");

# Test Step #6:
# Check that endpoint's DefaultDirectory attribute is /tmp
ok(is_default_dir($endpoint_name, "/tmp"), "is_default_dir_still_tmp");

# Test Step #7
# Set up server with (Public=False, DefaultDirectory="/home")
ok(setup_server($endpoint_name, 0, "/home"), "setup_server_non_public_home");

# Test Step #8:
# Check that endpoint's Public attribute is False
ok(!is_endpoint_public($endpoint_name), "is_endpoint_still_non_public");

# Test Step #9:
# Check that endpoint's DefaultDirectory attribute is /home
ok(is_default_dir($endpoint_name, "/home"), "is_default_dir_home");

# Test Step #10:
# Set up server with (Public=True, DefaultDirectory="/tmp")
# Change both at once
ok(setup_server($endpoint_name, 1, "/tmp"), "setup_server_public_tmp");

# Test Step #11:
# Check that endpoint's Public attribute is True
ok(is_endpoint_public($endpoint_name), "is_endpoint_public_again");

# Test Step #12:
# Check that endpoint's DefaultDirectory attribute is "/tmp"
ok(is_default_dir($endpoint_name, "/tmp"), "is_default_dir_back_to_tmp");

# Clean up the services
cleanup($endpoint_name);

# Remove everything in GCMU dir
force_cleanup();

# vim: filetype=perl:
