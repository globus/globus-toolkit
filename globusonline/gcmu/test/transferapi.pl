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
use Test::More;
use LWP;
use URI::Escape;

# Prepare
my $base_url = "https://transfer.api.globusonline.org/v0.10";
my $user = $ENV{GLOBUSONLINE_USER};
my $password = $ENV{GLOBUSONLINE_PASSWORD};
my $ua = LWP::UserAgent->new();
my $access_token = get_access_token($user, $password);

sub get_access_token()
{
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

sub get_endpoint($)
{
    my $endpoint = shift;
    my $req;
    my $res;
    my $json;
    my $servers;
    my $escaped_user = uri_escape($user);

    # List $endpoint
    $req = HTTP::Request->new(GET =>
            "$base_url/endpoint/$escaped_user\%23$endpoint");
    $req->header('Authorization' => 'Globus-Goauthtoken ' . $access_token);
    $res = $ua->request($req);
    $json = $res->content();
    $json =~ s/": /" => /g;
    $json =~ s/false/0/g;
    $json =~ s/true/1/g;
    $json =~ s/null/undef/g;
    $json = eval $json;

    return $json;
}

1;
