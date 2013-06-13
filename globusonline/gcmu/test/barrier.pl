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
use LWP;
use JSON;

# Prepare
my $barrier_url = $ENV{BARRIER_URL};
my $job_id = $ENV{JOB_ID};
my $ua = LWP::UserAgent->new();
my $barrier_prefix = "";
my $barrier_print = sub (@_) { print @_};
my $json_parser = JSON->new();

sub set_barrier_prefix($)
{
    $barrier_prefix = $_[0];
}

sub set_barrier_print($)
{
    $barrier_print = $_[0];
}

sub rank(\@)
{
    my $i;
    my @barrier_response = @_;

    for (my $i = 0; $i < scalar(@barrier_response); $i++)
    {
        if ($barrier_response[$i]->{job_id} eq $job_id)
        {
            return $i;
        }
    }
    return undef;
}

sub barrier($\%)
{
    my $barrier_name = shift;
    my %data = @_;
    my $url;
    my $req;
    my $res;
    my $retry;
    my $json;
    my $data = \%data;

    $data->{job_id} = $job_id;

    $json = $json_parser->encode($data);

    $barrier_print->("Barrier input: $json");

    $url = "$barrier_url/barrier/$barrier_prefix$barrier_name/$job_id";
    $barrier_print->("Barrier url: $url");
    $req = HTTP::Request->new(POST => $url);
    $req->content_type("application/json");
    $req->content($json);
    $req->content_length(length($json));
    $res = $ua->request($req);

    if ($res->code == 202)
    {
        do
        {
            $url = "$barrier_url/barrier/$barrier_prefix$barrier_name";
            $req = HTTP::Request->new(GET => $url);
            $res = $ua->request($req);

            if ($res->code() == 503)
            {
                $retry = $res->header("Retry-After");
                if ($retry)
                {
                    sleep(int($retry));
                }
            }
            elsif ($res->code() == 404)
            {
                return "ERROR";
            }
        } while ($res->code() != 200);
    } else {
        return "ERROR: " . $res->code();
    }

    $json = $json_parser->decode($res->content());

    $barrier_print->("Barrier output: ". $res->content());

    return $json;
}

1;

# vim: filetype=perl :
