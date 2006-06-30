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

my $buffer_size=2048;
my $test_name="framework";

#setup different driver combinations
my @drivers;
push(@drivers, "");
push(@drivers, "-D bounce");
push(@drivers, "-D bounce -D verify -D bounce");

my @thr_cnts;
push(@thr_cnts, "1");
push(@thr_cnts, "3");
push(@thr_cnts, "5");

sub basic_tests
{
    my $inline_finish="-i";
    my $server_flag="-s";
    my $sd = time % 1000;

    foreach(@drivers)
    {
        my $d=$_;
        foreach(@thr_cnts)
        {
            $ENV{"GLOBUS_CALLBACK_POLLING_THREADS"} = "$_";
            for(my $j = 0; $j < 10; $j++)
            {
                for(my $count = 1; $count <= 32; $count *= 2)
                {
                    push(@tests, "$test_name -X $sd -w $count -r $count $d -W 524288 -R 524288 $inline_finish");
                    $sd++;
                }
                if($j == 5)
                {
                    $inline_finish="";
                }
            }
        }
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
        my $test_str="random.$cnt";
        &run_test("$test_exec $_", $test_str);
        $cnt++;
    }
}
