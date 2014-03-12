#! /usr/bin/perl

# 
# Copyright 1999-2006 University of Chicago
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
use warnings;
use Test::More;
use IPC::Open2 qw(open2);

my $type = 0;
if(@ARGV == 1)
{
    $type = 1;
}

my @tests;
my @todo;
my $test_exec="./http_put_test";
my $data_dir=$ENV{TEST_DATA_DIR};
if (!$data_dir)
{
    $data_dir = "";
}

if (! -r "${data_dir}headers")
{
    print STDERR "Can't find data.\n";
    exit(99);
}
my @test_files = ("${data_dir}headers",
             "${data_dir}long-headers",
             "${data_dir}large-file");
my @versions = ('', 'HTTP/1.0', 'HTTP/1.1');
my @buffers = (0, 10000, 1000000);

for my $file (@test_files) {
    for my $client_version (@versions) {
        for my $server_version (@versions) {
            for my $client_buffer (@buffers) {
                for my $server_buffer (@buffers) {
                    my @client_args = ('-c');
                    my @server_args = ('-s');

                    push(@client_args, "-f", $file);
                    push(@server_args, "-f", $file);

                    if ($client_version ne '') {
                        push(@client_args, "-v", $client_version);
                    }
                    if ($server_version ne '') {
                        push(@server_args, "-v", $server_version);
                    }
                    if ($client_buffer != 0) {
                        push(@client_args, "-b", $client_buffer);
                    }
                    if ($server_buffer != 0) {
                        push(@server_args, "-b", $server_buffer);
                    }

                    my $name .= "Client:$client_version+$client_buffer-Server:$server_version+$server_buffer";
                    $name =~ s|HTTP/||g;

                    push (@tests, [[@client_args], [@server_args], $name]);
                }
            }
        }
    }
}


plan tests => scalar(@tests), todo => \@todo;
foreach my $testcase (@tests)
{
    my $result;
    my ($client_in, $client_out, $server_in, $server_out);
    my ($client_pid, $server_pid);
    $client_pid = open2($client_out, $client_in, $test_exec, @{$testcase->[0]});
    $server_pid = open2($server_out, $server_in, $test_exec, @{$testcase->[1]});
    my $input = <$server_out>;
    close($server_in);
    close($server_out);
    if (!$input) {
        ok(0, $_->[2]);
        close($client_in);
        close($client_out);
        waitpid($server_pid, 0);
        waitpid($client_pid, 0);
        next;
    }
    print $client_in $input;
    close($client_in);
    local ($/);
    waitpid($server_pid, 0);
    waitpid($client_pid, 0);
    $result = <$client_out>;
    $result =~ s/\s*$//;
    close($client_out);

    ok($result eq 'Success', $testcase->[2]);
}
