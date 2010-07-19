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

my @build_tests = qw(
            basic-test.pl
            close-barrier-test.pl
            failure-test.pl
            read-barrier-test.pl
            timeout-test.pl
            random-test.pl
            server-test.pl
            verify-test.pl
            );

my $filename="all_tests.txt";
unlink($filename);
foreach(@build_tests)
{
    my $cmd = "$_ P >> $filename";
    system($cmd);
}

push(@tests, "-D $filename");
push(@tests, "-A -D $filename");

my $cnt=0;
plan tests => scalar(@tests), todo => \@todo;
foreach(@tests)
{
    my $test_str="ALL.$cnt";
    &run_test("$test_exec $_", $test_str);
    $cnt++;
}
