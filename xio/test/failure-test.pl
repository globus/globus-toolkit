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
push(@drivers, "");
push(@drivers, "-D debug");

my @failures;
push(@failures, "-F 1");
push(@failures, "-F 2");
push(@failures, "-F 5");
push(@failures, "-F 6");
push(@failures, "-F 7");
push(@failures, "-F 8");
push(@failures, "-F 9");
push(@failures, "-F 10");

sub failure_tests
{
    my $inline_finish="-i";

    for(my $i = 0; $i < 2; $i++)
    {
        foreach(@drivers)
        {
            my $d=$_;
            foreach(@failures)
            {
                my $f=$_;
                push(@tests, "$test_name $f -w 1 -r 1 -s $inline_finish $d");
            }
        }
        $inline_finish="";
    }
}

&failure_tests();
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
    my $cnt=0;
    foreach(@tests)
    {
        my $test_str="fail_test.$cnt";
        &run_test("$test_exec $_", $test_str);
        $cnt++;
    }
}
