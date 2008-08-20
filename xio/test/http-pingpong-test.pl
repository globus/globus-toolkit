#! /usr/bin/env perl

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
use POSIX;
use Test;

my $type = 0;
if(@ARGV == 1)
{
    $type = 1;
}

my @tests;
my @todo;
my $test_exec="./http_pingpong_test";
my $data_dir=$ENV{GLOBUS_LOCATION}."/share/globus_xio_test";

                    my $client_args = '-c ';
                    my $server_args = '-s ';

                    push (@tests, [$client_args, $server_args]);


if($type == 1)
{
    foreach (@ARGV) {
        print "$test_exec $tests[$_]->[1] | $test_exec $tests[$_]->[0]\n";
    }
}
else
{
    plan tests => scalar(@tests), todo => \@todo;
    foreach(@tests)
    {
        my $result;
        chomp ($result = `$test_exec $_->[1]  | $test_exec $_->[0]`);

        ok($result, 'Success');
    }
}
