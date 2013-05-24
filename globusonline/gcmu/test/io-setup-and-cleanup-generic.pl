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

use strict;
use File::Path;
use File::Temp;
use Test::More;

plan tests => 4;

# Prepare
my $config_file = "test-io.conf";

# Test Step #1:
# Setup ID server
ok(setup_server() == 0, "setup_server");

# Test Step #2:
# Is GridFTP server running?
ok(is_gridftp_running() == 0, "is_gridftp_running");

# Test Step #3:
# Clean up the services
ok(cleanup() == 0, "cleanup");

# Test Step #4:
# Is GridFTP server running?
ok(is_gridftp_running() == 1, "is_gridftp_not_running");

# Remove everything in GCMU dir
force_cleanup();

sub setup_server()
{
    my @cmd = ("globus-connect-multiuser-setup", "-c", $config_file);

    return system(@cmd);
}

sub is_gridftp_running()
{
    my @cmd = ("/etc/init.d/globus-gridftp-server", "status");

    return system(@cmd);
}

sub cleanup()
{
    my @cmd;
    my $rc;

    $cmd[0] = "globus-connect-multiuser-cleanup";
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
