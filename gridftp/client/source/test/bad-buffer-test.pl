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

#
# Try reading an url by passing in a bad data buffer

use strict;
use POSIX;
use Test::More;
use File::Basename;
use lib dirname($0);
use FtpTestLib;

my $test_exec = './bad-buffer-test';

my @tests;
my @todo;

my ($proto) = setup_proto();
my ($source_host, $source_file, $local_copy) = setup_remote_source();

# Test 1: Bad buffer test
# Success if the transfer fails with exit code 2
sub bad_buffer
{
    my ($errors,$rc) = ("",0);
    my ($output);

    my $command = "$test_exec -s $proto$source_host$source_file";
    $errors = run_command($command, 2);

    ok($errors eq "", "bad_buffer $command");
}
push(@tests, "bad_buffer");

if(defined($ENV{FTP_TEST_RANDOMIZE}))
{
    shuffle(\@tests);
}

if(@ARGV)
{
    plan tests => scalar(@ARGV);

    foreach (@ARGV)
    {
        eval "&$tests[$_-1]";
    }
}
else
{
    plan tests => scalar(@tests), todo => \@todo;

    foreach (@tests)
    {
        eval "&$_";
    }
}
