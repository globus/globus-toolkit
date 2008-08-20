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
my $test_name="close_barrier";

my $inline_finish;
my $buffer_size=2048;
my $c;

# setup different chunk sizes
my @chunk_sizes;
push(@chunk_sizes, "1024");
push(@chunk_sizes, "1924");
push(@chunk_sizes, "2048");

#setup different driver combinations
my @drivers;
push(@drivers, "");
push(@drivers, "-D debug");
push(@drivers, "-D bounce");
push(@drivers, "-D debug -D bounce");
push(@drivers, "-D bounce -D debug");
#push(@drivers, "-D null -D debug");
push(@drivers, "-D debug -D bounce -D debug");
#push(@drivers, "-D bounce -D null -D bounce");

sub close_barrier
{
    my $inline_finish="-i";

    for(my $i = 0; $i < 2; $i++)
    {
        foreach(@chunk_sizes)
        {
            my $c = $_;
            foreach(@drivers)
            {
                push(@tests, "$test_name -w 1 -r 0 -c $c -b $buffer_size $inline_finish $_");
                push(@tests, "$test_name -w 0 -r 1 -c $c -b $buffer_size $inline_finish $_");
                for(my $write_count = 1; $write_count <= 16; $write_count *= 4)
                {
                    for(my $read_count = 1; $read_count <= 16; $read_count *= 4)
                    {
                        push(@tests, "$test_name -w $write_count -r $read_count -c $c -b $buffer_size $inline_finish $_");
                    }
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
