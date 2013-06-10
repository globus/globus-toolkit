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
use JSON;
use Test::More;
use LWP;
use URI::Escape;

# Prepare
my $token_host;
my $base_url;
my $instance = $ENV{GLOBUSONLINE_INSTANCE} || "Production";
my $user = $ENV{GLOBUSONLINE_USER};
my $password = $ENV{GLOBUSONLINE_PASSWORD};
my $ua = LWP::UserAgent->new();
my $access_token;
my $json_parser = JSON->new();

if ($instance eq 'Test')
{
    $token_host = "graph.api.test.globuscs.info";
    $base_url = "https://transfer.test.api.globusonline.org/v0.10";
}
else
{
    $token_host = "nexus.api.globusonline.org";
    $base_url = "https://transfer.api.globusonline.org/v0.10";
}

$access_token = get_access_token($user, $password);

sub get_access_token()
{
    my $json;
    my $url;
    my $req;
    my $res;
    
    # Get access token
    $url = "https://$user:$password\@$token_host/goauth/token?grant_type=client_credentials";
    $req = HTTP::Request->new(GET => $url);
    $res = $ua->request($req);
    $json = $json_parser->decode($res->content());
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
    $json = $json_parser->decode($res->content());

    return $json;
}

sub autoactivate($)
{
    my $endpoint = shift;
    my $escaped_user = uri_escape($user);
    my $req;
    my $res;
    my $json;

    $req = HTTP::Request->new(POST =>
            "$base_url/endpoint/$escaped_user\%23$endpoint/autoactivate");
    $req->header('Authorization' => 'Globus-Goauthtoken ' . $access_token);
    $res = $ua->request($req);
    $json = $json_parser->decode($res->content());

    return $json;
}

sub activate($$$)
{
    my $endpoint = shift;
    my $username = shift;
    my $password = shift;
    my $escaped_user = uri_escape($user);
    my $req;
    my $res;
    my $activation_requirements;
    my $activation_data;
    my $json;

    $json = autoactivate($endpoint);
    $activation_data = [];
    for (my $i = 0; $i < scalar(@{$json->{DATA}}); $i++)
    {
        if ($json->{DATA}->[$i]->{type} eq 'myproxy')
        {
            push(@{$activation_data}, $json->{DATA}->[$i]);
        }
    }
    for (my $i = 0; $i < scalar(@{$activation_data}); $i++)
    {
        if ($activation_data->[$i]->{name} eq 'username')
        {
            $activation_data->[$i]->{value} = $username;
        }
        elsif ($activation_data->[$i]->{name} eq 'passphrase')
        {
            $activation_data->[$i]->{value} = $password;
        }
    }
    $activation_requirements = {
        DATA_TYPE => "activation_requirements",
        length => scalar(@{$activation_data}),
        DATA => $activation_data };

    $json = $json_parser->encode($activation_requirements);

    $req = HTTP::Request->new(POST =>
            "$base_url/endpoint/$escaped_user\%23$endpoint/activate");
    $req->header('Authorization' => 'Globus-Goauthtoken ' . $access_token);
    $req->header("Content-Length" => length($json));
    $req->content($json);
    $res = $ua->request($req);
    $json = $json_parser->decode($res->content());

    return $json;
}

sub deactivate($)
{
    my $endpoint = shift;
    my $escaped_user = uri_escape($user);
    my $req;
    my $res;
    my $json;

    $req = HTTP::Request->new(POST =>
            "$base_url/endpoint/$escaped_user\%23$endpoint/deactivate");
    $req->header('Authorization' => 'Globus-Goauthtoken ' . $access_token);
    $res = $ua->request($req);
    $json = $json_parser->decode($res->content());

    return $json;
}

1;
