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
use Test::More;

plan tests => 7;

# Prepare
my $config_file = "test-io.conf";

# Test Step #1:
# Setup ID server
ok(setup_id_server() == 0, "setup_id_server");

# Test Step #2:
# Setup Web server
ok(setup_web_server() == 0, "setup_web_server");

# Test Step #3:
# Setup Web server
ok(setup_web_server() == 0, "setup_io_server");

# Test Step #4:
# Is GridFTP server running?
ok(is_gridftp_running() == 0, "is_gridftp_running");

# Test Step #5:
# Clean up the web server
ok(web_cleanup() == 0, "web_cleanup");

# Test Step #6:
# Clean up the ID server
ok(id_cleanup() == 0, "id_cleanup");

# Test Step #7:
# Clean up the IO server
ok(is_gridftp_running() == 1, "is_gridftp_not_running");

# Remove everything in GCMU dir
force_cleanup();

sub setup_id_server()
{
    my @cmd = ("globus-connect-multiuser-id-setup", "-c", $config_file);

    return system(@cmd);
}

sub setup_web_server()
{
    my @cmd = ("globus-connect-multiuser-web-setup", "-c", $config_file);

    return system(@cmd);
}

sub setup_io_server()
{
    my @cmd = ("globus-connect-multiuser-io-setup", "-c", $config_file);

    return system(@cmd);
}

sub is_gridftp_running()
{
    my @cmd = ("/etc/init.d/globus-gridftp-server", "status");

    return system(@cmd);
}

sub id_cleanup()
{
    my @cmd;
    my $rc;

    $cmd[0] = "globus-connect-multiuser-id-cleanup";
    $cmd[1] = "-c";
    $cmd[1] = $config_file;
    $rc = system(@cmd);
}

sub web_cleanup()
{
    my @cmd;
    my $rc;

    $cmd[0] = "globus-connect-multiuser-web-cleanup";
    $cmd[1] = "-c";
    $cmd[1] = $config_file;
    $rc = system(@cmd);
}

sub io_cleanup()
{
    my @cmd;
    my $rc;

    $cmd[0] = "globus-connect-multiuser-io-cleanup";
    $cmd[1] = "-c";
    $cmd[1] = $config_file;
    $rc = system(@cmd);
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
    File::Path::rmtree("/var/lib/globus-connect-multiuser");
    unlink("/var/lib/myproxy-oauth/myproxy-oauth.db");
    return 0;
}
