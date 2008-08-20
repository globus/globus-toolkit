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
my $test_name="block_barrier";

my $inline_finish;

#setup different driver combinations
my @drivers;
push(@drivers, "");
push(@drivers, "-D bounce");
push(@drivers, "-D bounce -D debug");
#push(@drivers, "-D bounce -D null");
push(@drivers, "-D debug -D bounce -D verify");

sub close_barrier
{
    my $inline_finish="-i";

    for(my $i = 0; $i < 2; $i++)
    {
        foreach(@drivers)
        {
            for(my $write_count = 0; $write_count < 3; $write_count++)
            {
                for(my $read_count = 0; $read_count < 3; $read_count++)
                {
                    push(@tests, "$test_name -w $write_count -r $read_count $inline_finish $_");
                }
            }
        }
        $inline_finish="";
    }
}

&close_barrier();
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
        my $test_str="$test_name.$cnt";
        &run_test("$test_exec $_", $test_str);
        $cnt++;
    }
}
