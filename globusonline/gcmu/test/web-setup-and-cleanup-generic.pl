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

use strict;
use File::Path;
use File::Temp;
use Test::More;
use LWP;

plan tests => 4;

# Prepare
my $config_file = "test-web.conf";
my $ua = LWP::UserAgent->new();

# Test Step #1:
# Setup ID server
ok(setup_server() == 0, "setup_server");

# Test Step #2:
# Contact OAuth server
ok(contact_oauth_server($ua) == 0, "contact_oauth_server");

# Test Step #3:
# Clean up the server
ok(cleanup() == 0, "web_cleanup");

# Test Step #4:
# Contact OAuth server
ok(contact_oauth_server($ua) != 0, "contact_disabled_oauth_server");

# Remove everything in GCMU dir
force_cleanup();

sub setup_server()
{
    my @cmd = ("globus-connect-multiuser-setup", "-c", $config_file);

    return system(@cmd);
}

sub contact_oauth_server($)
{
    my $ua = shift;
    my $req;
    my $res;

    $req = HTTP::Request->new(GET => "https://localhost/oauth/authorize");
    $res = $ua->request($req);
    return $res->code() == 403;
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
