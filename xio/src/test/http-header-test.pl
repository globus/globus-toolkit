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
use Test::More;

my $type = 0;
if(@ARGV == 1)
{
    $type = 1;
}

my @tests;
my @todo;
my $test_exec="./http_header_test";
my $data_dir = $ENV{'srcdir'};

if (! -d $data_dir && -r 'headers')
{
    $data_dir = '.';
}

push(@tests, "$data_dir/headers");
push(@tests, "$data_dir/long-headers");
push(@tests, "$data_dir/multi-line-header");
push(@tests, "$data_dir/multi-headers");

if($type == 1)
{
    foreach(@tests)
    {
        print "$_\n";
    }
}
else
{
    plan tests => scalar(@tests), todo => \@todo;
    foreach(@tests)
    {
        my $result;
        my $test_name = $_;
        chomp ($result = `$test_exec -s -f "$_" | $test_exec -c -f "$_"`);
        $test_name =~ s|.*/||;

        ok($result eq 'Success', $test_name);
    }
}
