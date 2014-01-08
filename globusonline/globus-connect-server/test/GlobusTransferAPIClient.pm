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

package GlobusTransferAPIClient;

use strict;
use HTML::Form;
use JSON;
use LWP;
use POSIX;
use URI::Escape;

our %token_hosts = (
    Test => "graph.api.test.globuscs.info",
    Production => "nexus.api.globusonline.org");
our %base_url = (
    Test => "https://transfer.test.api.globusonline.org/v0.10",
    Production => "https://transfer.api.globusonline.org/v0.10");
our %web_hosts = (
    Test => "test.globuscs.info",
    Production => "www.globusonline.org");

our $json_parser = JSON->new();

sub new($;%)
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = {
        instance => $ENV{GLOBUS_INSTANCE} || "Production",
        user => $ENV{GLOBUS_USER},
        password => $ENV{GLOBUS_PASSWORD},
        @_
    };
    if (! $self->{ua})
    {
        $self->{ua} = LWP::UserAgent->new(ssl_opts => {verify_hostname => 0 });
        $self->{ua}->cookie_jar({});
    }
    if (! $self->{token_host})
    {
        $self->{token_host} = $token_hosts{$self->{instance}};
    }
    if (! $self->{base_url})
    {
        $self->{base_url} = $base_url{$self->{instance}};
    }
    if (! $self->{web_host})
    {
        $self->{web_host} = $web_hosts{$self->{instance}};
    }

    bless $self, $class;
};

sub qualified_endpoint_name($$;%)
{
    my $self = shift;
    my $endpoint = shift;
    my %args = (
        escape => 1,
        @_);

    if ($endpoint =~ /#/) {
        if ($args{escape}) {
            return uri_escape($endpoint);
        } else {
            return $endpoint;
        }
    } elsif ($endpoint =~ /\%23/) {
        if ($args{escape}) {
            return $endpoint;
        } else {
            return uri_unescape($endpoint);
        }
    } else {
        $endpoint = $self->{user} . "#$endpoint";
        if ($args{escape}) {
            return uri_escape($endpoint);
        } else {
            return $endpoint;
        }
    }
}

sub get_access_token($;%)
{
    my $self = shift;
    my %args = (
        user => $self->{user},
        password => $self->{password},
        token_host => $self->{token_host},
        @_);
    my $json;
    my $url;
    my $req;
    my $res;

    if (! $self->{access_token})
    {
        # Get access token
        $url = sprintf "https://\%s:\%s\@\%s/goauth/token?grant_type=client_credentials",
                $args{user}, $args{password}, $args{token_host};
        $req = HTTP::Request->new(GET => $url);
        $res = $self->{ua}->request($req);
        $json = $json_parser->decode($res->content());
        $self->{access_token} = $json->{'access_token'};
    }
    return $self->{access_token};
}

sub get_endpoint($$)
{
    my $self = shift;
    my $endpoint = $self->qualified_endpoint_name(shift);
    my $req;
    my $res;
    my $json;
    my $servers;

    # List $endpoint
    $req = HTTP::Request->new(GET =>
            $self->{base_url} . "/endpoint/$endpoint");
    $req->header('Authorization' => 'Globus-Goauthtoken '
        . $self->get_access_token());
    $res = $self->{ua}->request($req);
    $json = $json_parser->decode($res->content());

    return $json;
}

sub autoactivate($$)
{
    my $self = shift;
    my $endpoint = $self->qualified_endpoint_name(shift);
    my $req;
    my $res;
    my $json;

    $req = HTTP::Request->new(POST =>
            $self->{base_url} . "/endpoint/$endpoint/autoactivate");
    $req->header('Authorization' => 'Globus-Goauthtoken '
        . $self->get_access_token());
    $res = $self->{ua}->request($req);
    $json = $json_parser->decode($res->content());

    return $json;
}

sub activate($$$$)
{
    my $self = shift;
    my $endpoint = $self->qualified_endpoint_name(shift);
    my $username = shift;
    my $password = shift;
    my $req;
    my $res;
    my $activation_requirements;
    my $activation_data;
    my $json;
    my $using_myproxy = undef;

    $json = $self->autoactivate($endpoint);
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
                $self->{base_url}."/endpoint/$endpoint/activate");
        $req->header('Authorization' => 'Globus-Goauthtoken '
            . $self->get_access_token());
        $req->header("Content-Length" => length($json));
        $req->header("Content-Type" => 'application/json');
        $req->content($json);
        $res = $self->{ua}->request($req);
        $json = $json_parser->decode($res->content());
    }
    elsif ($json->{oauth_server})
    {
        my $oauth_server = $json->{oauth_server};
        my $content;
        # TODO: implement for non-production instances

        # Authenticate with GO web page to get saml token
        $req = HTTP::Request->new(POST =>
            sprintf "https://\%s/service/graph/authenticate",
                    $self->{web_host});
        $content = $json_parser->encode({
                username=>$self->{user},
                password=>$self->{password}});
        $req->header("Content-Type", "application/json");
        $req->header("Content-Length", length($content));
        $req->content($content);
        $res = $self->{ua}->request($req);

        # Visit activation page (not sure how this form gets generated from the
        # mess of javascript on globusonline)
        $req = HTTP::Request->new(POST =>
            "https://www.globusonline.org/service/graph/authenticate_oauth");
        $content = sprintf "server=$oauth_server&return_path=https\%3A\%2F\%2F%s\%2Fxfer\%2FActivateEndpoints\%3Fep\%3D$endpoint\%26activate_oauth\%3D$oauth_server", $self->{web_host};
        $req->header("Content-Type", "application/x-www-form-urlencoded");
        $req->header("Content-Length", length($content));
        $req->header(Referer => sprintf 'https://%s/xfer/ActivateEndpoints',
                $self->{web_host});
        
        $req->content($content);

        $res = $self->{ua}->request($req);

        if ($res->code == 302)
        {
            # This redirects me to oauth server
            $res = $self->{ua}->get($res->header('location'));
            my $form = HTML::Form->parse($res);
            $form->param('username', $username);
            $form->param('passphrase', $password);
            $req = $form->click();
            $res = $self->{ua}->request($req);

            if ($res->code == 301)
            {
                # This redirects me back to globusonline with params so it
                # can fetch the credential from oauth
                $req = HTTP::Request->new(GET => $res->header('location'));
                $req->header(Referer => $res->request->url);
                $res = $self->{ua}->request($req);

                # Now to get activation result in json form, we'll poke the
                # autoactivate once more
                $json = $self->autoactivate($endpoint);
            }
        }
    }

    return $json;
}

sub deactivate($$)
{
    my $self = shift;
    my $endpoint = $self->qualified_endpoint_name(shift);
    my $req;
    my $res;
    my $json;

    $req = HTTP::Request->new(POST =>
            $self->{base_url}."/endpoint/$endpoint/deactivate");
    $req->header('Authorization' => 'Globus-Goauthtoken ' .
            $self->get_access_token());
    $res = $self->{ua}->request($req);
    $json = $json_parser->decode($res->content());

    return $json;
}

sub transfer($$$$$)
{
    my $self = shift;
    my $source_endpoint = $self->qualified_endpoint_name(shift, escape=>0);
    my $source_path = shift;
    my $destination_endpoint = $self->qualified_endpoint_name(shift, escape=>0);
    my $destination_path = shift;
    my $submission_id;
    my $req;
    my $res;
    my $input;
    my $json;
    my $task_id;
    my $done = undef;
    my $deadline;
    my $giveup;

    $req = HTTP::Request->new(GET => $self->{base_url}."/submission_id");
    $req->header('Authorization' => 'Globus-Goauthtoken '
            . $self->get_access_token());
    $res = $self->{ua}->request($req);

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
    $req = HTTP::Request->new(POST => $self->{base_url}."/transfer");
    $req->header(Authorization => 'Globus-Goauthtoken ' . $self->get_access_token());
    $req->header('Content-Type' => 'application/json');
    $req->header('Content-Length' => length($json));
    $req->content($json);

    $json = $json_parser->decode($self->{ua}->request($req)->content);
    $task_id = $json->{task_id};

    if ($task_id eq '')
    {
        return { status => "FAILED" };
    }

    $giveup = time() + 301;

    do
    {
        $req = HTTP::Request->new(GET => $self->{base_url}."/task/$task_id");
        $req->header('Authorization' => 'Globus-Goauthtoken ' . $self->get_access_token());
        $json = $json_parser->decode($self->{ua}->request($req)->content);

        $done = $json->{status} eq "SUCCEEDED" || $json->{status} eq "FAILED";
        if (!$done)
        {
            sleep(30);
            if (time() > $giveup)
            {
                return { status => "FAILED" };
            }
        }
    } while(!$done);

    return $json;
}

sub shared_endpoint_create($$$$)
{
    my $self = shift;
    my $doc = {
        DATA_TYPE => 'shared_endpoint',
        name => $self->qualified_endpoint_name(shift, escape=>0),
        host_endpoint => $self->qualified_endpoint_name(shift, escape=>0),
        host_path => shift
    };
    my ($json, $req, $res);

    $json = $json_parser->encode($doc);

    $req = HTTP::Request->new(POST =>
            $self->{base_url} . "/shared_endpoint");
    $req->header(Authorization => 'Globus-Goauthtoken '
            . $self->get_access_token());
    $req->header('Content-Type' => 'application/json');
    $req->header('Content-Length' => length($json));
    $req->content($json);

    $res = $self->{ua}->request($req);
    return $json_parser->decode($res->content);
}

sub endpoint_access_add($$;%)
{
    my $self = shift;
    my $endpoint = $self->qualified_endpoint_name(shift);
    my %doc = (
        DATA_TYPE => "access",
        id => time(),
        path => '/',
        principal_type => 'user',
        principal => $self->{user},
        permissions => 'r',
        @_
    );
    my ($json, $req, $res);

    $json = $json_parser->encode(\%doc);

    $req = HTTP::Request->new(POST =>
            $self->{base_url}."/endpoint/$endpoint/access");
    $req->header(Authorization => 'Globus-Goauthtoken ' . $self->get_access_token());
    $req->header('Content-Type' => 'application/json');
    $req->header('Content-Length' => length($json));
    $req->content($json);

    $res = $self->{ua}->request($req);
    return $json_parser->decode($res->content);
}

1;

# vim: filetype=perl :
