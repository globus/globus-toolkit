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

my @tests;
my $test_exec="./http_pingpong_test";

my @client_args = ('-c');
my @server_args = ('-s');

plan tests => 1;

my $result;
my ($client_in, $client_out, $server_in, $server_out);
my ($client_pid, $server_pid);
$client_pid = open2($client_out, $client_in, $test_exec, '-c');
$server_pid = open2($server_out, $server_in, $test_exec, '-s');
my $input = <$server_out>;
close($server_in);
close($server_out);
if (!$input) {
    ok(0, $_->[2]);
    close($client_in);
    close($client_out);
    waitpid($server_pid, 0);
    waitpid($client_pid, 0);
    exit(1);
}
print $client_in $input;
close($client_in);
local ($/);
waitpid($server_pid, 0);
waitpid($client_pid, 0);
$result = <$client_out>;
$result =~ s/\s*$//;
close($client_out);

print STDERR "# $result\n";
ok($result eq 'Success', "http_pingping_test");
