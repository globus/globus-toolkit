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

plan tests => 3;

# Prepare
my $user = $ENV{GLOBUSONLINE_USER};
my $password = $ENV{GLOBUSONLINE_PASSWORD};
my $ua = LWP::UserAgent->new();
my $access_token = get_access_token($user, $password);
my $random = int(1000000*rand());
my $endpoint = "MULTI$random";
my $base_url = "https://transfer.api.globusonline.org/v0.10";
my $config_file = "multi-node-test.conf";
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
ok(gcmu_setup($endpoint) == 0, "$test_mode:create_endpoint");

# Test Step #2:
# Get number of servers on endpoint, assert == 1
ok(count_servers($user, $endpoint, $access_token) == 1, "$test_mode:count_servers1");

# Test Step #3:
# Clean up gcmu
ok(cleanup() == 0, "$test_mode:cleanup");

sub get_access_token($$)
{
    my $user = uri_escape($_[0]);
    my $password = uri_escape($_[1]);
    my $json;
    my $url;
    my $req;
    my $res;
    my $access_token;
    my $random = int(1000000*rand());
    
    # Get access token
    $url = "https://$user:$password\@nexus.api.globusonline.org/goauth/token?grant_type=client_credentials";
    $req = HTTP::Request->new(GET => $url);
    $res = $ua->request($req);
    $json = $res->content();
    $json =~ s/": /" => /g;
    $json = eval $json;
    return $json->{'access_token'};
}

sub count_servers($$$)
{
    my $user = uri_escape($_[0]);
    my $endpoint = $_[1];
    my $access_token = $_[2];
    my $req;
    my $res;
    my $json;
    my $servers;

    # List endpoint $endpoint
    $req = HTTP::Request->new(GET =>
            "$base_url/endpoint/$user\%23$endpoint");
    $req->header('Authorization' => 'Globus-Goauthtoken ' . $access_token);
    $res = $ua->request($req);
    $json = $res->content();
    $json =~ s/": /" => /g;
    $json =~ s/false/0/g;
    $json =~ s/true/1/g;
    $json =~ s/null/undef/g;
    $json = eval $json;
    if (!$json) {
        return $@;
    }
    return scalar(map($_->{hostname}, @{$json->{DATA}}));
}

sub cleanup
{
    my @cmd;
    my $rc;

    $cmd[0] = "globus-connect-multiuser-cleanup";
    $cmd[1] = "-c";
    $cmd[1] = $config_file;
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
    return $rc;
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
    return system(@cmd);
}
