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

# Prepare
my $barrier_url = $ENV{BARRIER_URL};
my $job_id = $ENV{JOB_ID};
my $ua = LWP::UserAgent->new();
my $barrier_prefix = "";

sub set_barrier_prefix($)
{
    $barrier_prefix = $_[0];
}

sub rank(\%)
{
    my $i;
    my %barrier_response = @_;

    for (my $i = 0; $i < scalar(keys(%barrier_response)); $i++)
    {
        if ($barrier_response{$i}->{job_id} == $job_id)
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
    my $content;
    my $url;
    my $req;
    my $res;
    my $retry;
    my $json;

    $content = "{\n";
    $content .= join(",\n", "\"job_id\": \"$job_id\"",
            map { "\"$_\":  \"$data{$_}\" " } keys(%data));
    $content .= "\n}\n";

    
    $url = "$barrier_url/barrier/$barrier_prefix$barrier_name/$job_id";
    $req = HTTP::Request->new(POST => $url);
    $req->content_type("application/json");
    $req->content($content);
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

    $json = $res->content();
    $json =~ s/": /" => /g;
    $json = eval $json;

    return $json;
}

1;
