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

 require "test-common.pl";

my $type = 0;
if(@ARGV == 1)
{
    $type = 1;
}

my @tests;
my @todo;
my $test_exec="./framework_test";

my $inline_finish;
my $buffer_size=2048;
my $test_name="framework";

#setup different driver combinations
my @drivers;
push(@drivers, "-D verify");
push(@drivers, "-D verify -D debug");
push(@drivers, "-D debug -D verify");
push(@drivers, "-D verify -D bounce");
push(@drivers, "-D bounce -D verify");
push(@drivers, "-D debug -D bounce -D verify");
push(@drivers, "-D verify -D debug -D bounce");

sub basic_tests
{
    my $inline_finish="-i";
    my $s="";

    for(my $j = 0; $j < 2; $j++)
    {
        for(my $i = 0; $i < 2; $i++)
        {
            foreach(@drivers)
            {
                my $d=$_;
                push(@tests, "$test_name -s -w 1 -r 0 $inline_finish $d");
                push(@tests, "$test_name -s -w 0 -r 1 $inline_finish $d");
                push(@tests, "$test_name -s -w 0 -r 0 $inline_finish $d");
            }
            $inline_finish="";
        }
        $s="-s";
    }
}

&basic_tests();

if($type == 1)
{
    foreach(@tests)
    {
        print "$_\n";
    }
}
else
{
    my $cnt=0;
    plan tests => scalar(@tests), todo => \@todo;
    foreach(@tests)
    {
        my $test_str="verify.$cnt";
        &run_test("$test_exec $_", $test_str);
        $cnt++;
    }
}
