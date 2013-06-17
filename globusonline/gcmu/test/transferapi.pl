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
use HTML::Form;
use JSON;
use Test::More;
use LWP;
use URI::Escape;

# Prepare
my $token_host;
my $base_url;
my $instance = $ENV{GLOBUSONLINE_INSTANCE} || "Production";
my $go_user = $ENV{GLOBUSONLINE_USER};
my $go_password = $ENV{GLOBUSONLINE_PASSWORD};
my $ua = LWP::UserAgent->new();
$ua->cookie_jar( {} );


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

$access_token = get_access_token($go_user, $go_password);

sub get_access_token($$)
{
    my ($user, $password) = @_;
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
    my $escaped_user = uri_escape($go_user);

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
    my $escaped_user = uri_escape($go_user);
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
    my $escaped_user = uri_escape($go_user);
    my $req;
    my $res;
    my $activation_requirements;
    my $activation_data;
    my $json;
    my $using_myproxy = undef;

    $json = autoactivate($endpoint);
    $activation_data = [];
    for (my $i = 0; $i < scalar(@{$json->{DATA}}); $i++)
    {
        if ($json->{DATA}->[$i]->{type} eq 'myproxy')
        {
            push(@{$activation_data}, $json->{DATA}->[$i]);
            $using_myproxy = 1;
        }
    }
    if ($using_myproxy)
    {
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
    }
    elsif ($json->{oauth_server})
    {
        my $oauth_server = $json->{oauth_server};
        my $content;
        # TODO: implement for non-production instances

        # Authenticate with GO web page to get saml token
        $req = HTTP::Request->new(POST => 'https://www.globusonline.org/service/graph/authenticate');
        $content = $json_parser->encode({username=>$go_user, password=>$go_password});
        $req->header("Content-Type", "application/json");
        $req->header("Content-Length", length($content));
        $req->content($content);
        $res = $ua->request($req);

        # Visit activation page (not sure how this form gets generated from the
        # mess of javascript on globusonline)
        $req = HTTP::Request->new(POST =>
            "https://www.globusonline.org/service/graph/authenticate_oauth");
        $content = "server=$oauth_server&return_path=https%3A%2F%2Fwww.globusonline.org%2Fxfer%2FActivateEndpoints%3Fep%3D$escaped_user%25$endpoint%26activate_oauth%3D$oauth_server";
        $req->header("Content-Type", "application/x-www-form-urlencoded");
        $req->header("Content-Length", length($content));
        $req->header(Referer => 'https://www.globusonline.org/xfer/ActivateEndpoints');
        
        $req->content($content);

        $res = $ua->request($req);

        if ($res->code == 302)
        {
            # This redirects me to oauth server
            $res = $ua->get($res->header('location'));
            my $form = HTML::Form->parse($res);
            $form->param('username', $username);
            $form->param('passphrase', $password);
            $req = $form->click();
            $res = $ua->request($req);

            if ($res->code == 301)
            {
                # This redirects me back to globusonline with params so it
                # can fetch the credential from oauth
                $req = HTTP::Request->new(GET => $res->header('location'));
                $req->header(Referer => $res->request->url);
                $res = $ua->request($req);

                # Now to get activation result in json form, we'll poke the
                # autoactivate once more
                $json =  autoactivate($endpoint);
            }
        }

    }

    return $json;
}

sub deactivate($)
{
    my $endpoint = shift;
    my $escaped_user = uri_escape($go_user);
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

sub transfer($$$$)
{
    my $source_endpoint = shift;
    my $source_path = shift;
    my $destination_endpoint = shift;
    my $destination_path = shift;
    my $submission_id;
    my $req;
    my $res;
    my $input;
    my $json;
    my $task_id;
    my $done = undef;
    my $deadline;

    $req = HTTP::Request->new(GET => "$base_url/submission_id");
    $req->header('Authorization' => 'Globus-Goauthtoken ' . $access_token);
    $res = $ua->request($req);

    $submission_id = $json_parser->decode($res->content())->{value};
    $deadline = POSIX::strftime("%Y-%m-%d %H:%M:%S", gmtime(time() + 300));
    $input = {
        DATA_TYPE => "transfer",
        submission_id => $submission_id,
        sync_level => JSON::null,
        source_endpoint => $source_endpoint,
        destination_endpoint => $destination_endpoint,
        deadline => $deadline,
        notify_on_succeeded => JSON::false,
        notify_on_failed => JSON::false,
        notify_on_inactive => JSON::false,
        length => 1,
        DATA => [
            {
                DATA_TYPE => "transfer_item",
                source_path => $source_path,
                destination_path => $destination_path
            }
        ]
    };
    $json = $json_parser->encode($input);
    $req = HTTP::Request->new(POST => "$base_url/transfer");
    $req->header(Authorization => 'Globus-Goauthtoken ' . $access_token);
    $req->header('Content-Type' => 'application/json');
    $req->header('Content-Length' => length($json));
    $req->content($json);

    $json = $json_parser->decode($ua->request($req)->content);
    $task_id = $json->{task_id};

    do
    {
        $req = HTTP::Request->new(GET => "$base_url/task/$task_id");
        $req->header('Authorization' => 'Globus-Goauthtoken ' . $access_token);
        $json = $json_parser->decode($ua->request($req)->content);

        $done = $json->{status} eq "SUCCEEDED" || $json->{status} eq "FAILED";
        if (!$done)
        {
            sleep(30);
        }
    } while(!$done);

    return $json;
}

1;

# vim: filetype=perl :
