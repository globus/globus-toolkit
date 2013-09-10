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
use File::Temp;
use IPC::Open3;
use Test::More;
use LWP;

my $config_file = "test-web.conf";

sub setup_server()
{
    my @cmd = ("globus-connect-multiuser-setup", "-c", $config_file, "-v");
    my ($pid, $in, $out, $err);
    $pid = open3($in, $out, $err, @cmd);
    close($in);
    waitpid($pid, 0);
    my $rc = $? >> 8;
    print STDERR join("", <$out>);
    print STDERR join("", <$err>);

    return $rc == 0;
}

sub contact_oauth_server($)
{
    my $ua = shift;
    my $req;
    my $res;

    $req = HTTP::Request->new(GET => "https://127.0.0.1/oauth/authorize");
    $res = $ua->request($req);
    return $res->code() == 403;
}

sub cleanup()
{
    my @cmd = ("globus-connect-multiuser-cleanup", "-c", $config_file, "-v");
    my ($pid, $in, $out, $err);
    $pid = open3($in, $out, $err, @cmd);
    close($in);
    waitpid($pid, 0);
    my $rc = $? >> 8;
    print STDERR join("", <$out>);
    print STDERR join("", <$err>);

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
    File::Path::rmtree("/var/lib/globus-connect-multiuser");
    unlink("/var/lib/myproxy-oauth/myproxy-oauth.db");
    return 0;
}

# Prepare
plan tests => 3;

my $ua = LWP::UserAgent->new();

# Test Step #1:
# Setup ID server
ok(setup_server(), "setup_server");

# Test Step #2:
# Contact OAuth server
ok(contact_oauth_server($ua), "contact_oauth_server");

# Test Step #3:
# Clean up the server
ok(cleanup(), "web_cleanup");

# Remove everything in GCMU dir
force_cleanup();
