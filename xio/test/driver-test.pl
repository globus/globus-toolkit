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

my $test_driver;
if(@ARGV == 1)
{
    $test_driver = $ARGV[0];
}
else
{
    die "provide a driver name please";
}

my @tests;
my @todo;
my $test_exec="./framework_test";
my $test_name="framework";

my $inline_finish;
my $buffer_size=2048;
my $c;

# setup different chunk sizes
my @chunk_sizes;
push(@chunk_sizes, "1024");
push(@chunk_sizes, "1924");
push(@chunk_sizes, "2048");

# setup different driver combinations
my @drivers;
push(@drivers, "-D $test_driver");
#push(@drivers, "-D debug -D $test_driver");
#push(@drivers, "-D debug -D $test_driver -D debug");
#push(@drivers, "-D bounce -D $test_driver");
#push(@drivers, "-D $test_driver -D bounce");

sub build_test_list
{
    my $inline_finish="-i";

    for(my $i = 0; $i < 2; $i++)
    {
        foreach(@chunk_sizes)
        {
            my $c = $_;

            foreach(@drivers)
            {
                my $d = $_;
                for(my $write_count = 1; $write_count <= 16; $write_count *= 4)
                {
                    for(my $read_count = 1; $read_count <= 16; $read_count *= 4)
                    {
                        push(@tests, "$test_name -w $write_count -r $read_count -c $c -b $buffer_size $inline_finish $d");
                    }
                }
            }
        }
        $inline_finish="";
    }
}

&build_test_list();
plan tests => scalar(@tests), todo => \@todo;
my $cnt=0;
foreach(@tests)
{
    my $test_str="$test_name.$cnt";
    &run_test("$test_exec $_", $test_str);
    $cnt++;
}
