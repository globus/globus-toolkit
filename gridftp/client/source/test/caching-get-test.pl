#! /usr/bin/perl

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
# Test to exercise the "get" functionality of the Globus FTP client library.
#

use strict;
use POSIX;
use File::Basename;
use lib dirname($0);
use Test::More;
use FtpTestLib;
use File::Spec;
use lib dirname($0);
require 'URL.pm';

my $test_exec = './caching-get-test';
my @tests;
my @todo;

my ($proto) = setup_proto();
my ($source_host, $source_file, $local_copy) = setup_remote_source();

# Test #1-2. Basic functionality: Do a simple get (twice, caching the url)
# of $test_url (with and without a valid proxy).
# Compare the resulting file with the real file
# Success if program returns 0, files compare,
# and no core file is generated, or no valid proxy, and program returns 1.
sub basic_func
{
    my ($use_proxy) = (shift);
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    if($use_proxy == 0)
    {
        FtpTestLib::push_proxy(File::Spec::->devnull());
    }
    
    my $command = "$test_exec -s $proto$source_host$source_file";
    $errors = run_command($command, $use_proxy ? 0 : -1, $tmpname);
    if($errors eq "" && $use_proxy)
    {
        my ($newtmp)=(POSIX::tmpnam());
	system("cat \"$local_copy\" \"$local_copy\" > $newtmp");

	$errors .= compare_local_files($newtmp, $tmpname);

	unlink($newtmp);	
    }

    ok($errors eq "", "basic_func $use_proxy $command");
    unlink($tmpname);
    if($use_proxy == 0)
    {
        FtpTestLib::pop_proxy();
    }
}
push(@tests, "basic_func" . "(0);") unless $proto ne "gsiftp://"; #Use invalid proxy
push(@tests, "basic_func" . "(1);"); #Use proxy

# Test #3: Bad URL: Do a simple get (twice, caching the URL)
# of a non-existent file.
# Success if program returns 1 and no core file is generated.
sub bad_url
{
    my ($errors,$rc) = ("",0);
    my ($bogus_url) = new Globus::URL("$proto$source_host$source_file");

    $bogus_url->{path} = "$source_file/etc/no-such-file-here";
    
    my $command = "$test_exec -s ".$bogus_url->to_string();
    $errors = run_command($command, 2);

    ok($errors eq '', "bad_url $command");
}
push(@tests, "bad_url");

# Test #4-44: Do a simple get (twice, caching the URL) of $test_url,
# aborting at each possible position. Note that not all aborts
# may be reached.
# Success if no core file is generated for all abort points. (we could use
# a stronger measure of success here)
sub abort_test
{
    my ($errors,$rc) = ("", 0);
    my ($abort_point) = shift;

    my $command = "$test_exec -a $abort_point -s $proto$source_host$source_file";
    $errors = run_command($command, -2);

    ok($errors eq '', "abort_test $abort_point $command");
}
for(my $i = 1; $i <= 43; $i++)
{
    push(@tests, "abort_test($i);");
}

# Test #45-85. Restart functionality: Do a simple get (twice, caching the
# url) of $test_url, restarting at each plugin-possible point.
# Compare the resulting file with the real file
# Success if program returns 0, files compare,
# and no core file is generated.
sub restart_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($restart_point) = shift;

    unlink($tmpname);

    my $command = "$test_exec -r $restart_point -s $proto$source_host$source_file";
    $errors = run_command($command, 0, $tmpname);
    if($errors eq "")
    {
        my ($newtmp)=(POSIX::tmpnam());
        system("cat \"$local_copy\" \"$local_copy\" > $newtmp");

        $errors .= compare_local_files($newtmp, $tmpname);

        unlink($newtmp);	
    }

    ok($errors eq "", "restart_test $restart_point $command");

    unlink($tmpname);
}
for(my $i = 1; $i <= 43; $i++)
{
    push(@tests, "restart_test($i);");
}

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
