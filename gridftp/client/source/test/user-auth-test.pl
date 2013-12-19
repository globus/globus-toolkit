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
# Test to exercise the "get" functionality of the Globus FTP client
# library allowing a user-specified authorized certificate name.
#

use strict;
use POSIX;
use Test::More;
use File::Basename;
use lib dirname($0);
use FtpTestLib;

my $test_exec = './user-auth-test';
my @tests;
my @todo;

my ($proto) = setup_proto();
my ($source_host, $source_file, $local_copy) = setup_remote_source();

# Test #1. User specifies the correct authorization information.
# Success if program returns 0, files compare,
# and no core file is generated, or no valid proxy, and program returns 1.
sub correct_auth
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($hostname) = ();
    unlink($tmpname);

    if(exists $ENV{GLOBUS_FTP_CLIENT_TEST_SUBJECT})
    {
        $hostname = $ENV{GLOBUS_FTP_CLIENT_TEST_SUBJECT};
    }
    elsif(exists $ENV{GLOBUS_HOSTNAME})
    {
        $hostname = "host\@$ENV{GLOBUS_HOSTNAME}";
    }
    else
    {
        $hostname = `hostname`;
        $hostname = "host\@$hostname";
    }

    chomp($hostname);
    
    my $command = "$test_exec -s $proto$source_host$source_file -A '$hostname'";
    $errors = run_command($command, 0, $tmpname);
    if($errors eq "")
    {
        my $diffs = `diff $local_copy $tmpname | sed -e "s/^/# /"`;
        if($? != 0)
        {
            $errors .= "\n# Differences between /etc/group and output.";
            $errors .= "$diffs";
        }
    }
    
    ok($errors eq "", "correct_auth $command");
    unlink($tmpname);
}
push(@tests, "correct_auth");

# Test #2: User specifies incorrect authorization information.
# Success if program returns 1 and no core file is generated.
sub incorrect_auth
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($hostname) = ("googly_goodness");
    unlink($tmpname);

    my $command = "$test_exec -s $proto$source_host$source_file -A 'host\@$hostname'";
    $errors = run_command($command, 1, $tmpname);

    ok($errors eq "", "incorrect_auth $command");

    unlink($tmpname);
}
push(@tests, "incorrect_auth") unless $proto ne "gsiftp://";

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
