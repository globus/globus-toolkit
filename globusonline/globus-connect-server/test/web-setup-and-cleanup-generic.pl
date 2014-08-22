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
use IO::Socket::SSL;
use IPC::Open3;
use Test::More;
use LWP;

my $config_file = "test-web.conf";

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

sub setup_server()
{
    my @cmd = ("globus-connect-server-setup", "-c", $config_file, "-v");
    my $rc = diagsystem(@cmd);

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
    my @cmd = ("globus-connect-server-cleanup", "-c", $config_file, "-v");
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
    return 0;
}

# Prepare
plan tests => 3;

my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0, SSL_verify_mode => 'SSL_VERIFY_NONE' });

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
# vim: filetype=perl:
