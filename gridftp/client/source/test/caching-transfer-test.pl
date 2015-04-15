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
# Test to exercise the "3rd party transfer" functionality of the Globus
# FTP client library using URL caching.
#

use strict;
use POSIX;
use Test::More;
use File::Basename;
use lib dirname($0);
use FtpTestLib;
use File::Spec;

my $test_exec = './caching-transfer-test';
my @tests;
my @todo;

my ($proto) = setup_proto();
my ($source_host, $source_file, $local_copy) = setup_remote_source();
my ($dest_host, $dest_file) = setup_remote_dest();

# Test #1-2. Basic functionality: Do two transfers of test-file to/from
# localhost (with and without a valid proxy) using URL caching.
# Compare the resulting file with the real file
# Success if program returns 0, files compare,
# and no core file is generated, or no valid proxy, and program returns 1.
sub basic_func
{
    my ($use_proxy) = (shift);
    my ($errors,$rc) = ("",0);

    if($use_proxy == 0)
    {
        FtpTestLib::push_proxy(File::Spec::->devnull());
    }
    my $command = "$test_exec -s $proto$source_host$source_file -d $proto$dest_host$dest_file";
    $errors = run_command($command, $use_proxy ? 0 : -1);
    if($use_proxy && $errors eq "")
    {
        my ($output) = get_remote_file($dest_host, $dest_file);
        $errors = compare_local_files($local_copy, $output);
        unlink($output);
    }

    ok($errors eq "", "basic_func $use_proxy $command");
    if($use_proxy == 0)
    {
        FtpTestLib::pop_proxy();
    }
    
    clean_remote_file($dest_host, $dest_file);
}
push(@tests, "basic_func" . "(0);") unless $proto ne "gsiftp://"; #Use invalid proxy
push(@tests, "basic_func" . "(1);"); #Use proxy

# Test #3: Bad URL: Do a 3rd party transfer of a using a non-existent
# file from localhost twice using URL caching.
# Success if program returns 1 and no core file is generated.
sub bad_url_src
{
    my ($errors,$rc) = ("",0);

    my $command = "$test_exec -s $proto$source_host$source_file/etc/no-such-file-here -d $proto$dest_host$dest_file";
    $errors = run_command($command, 2);

    ok($errors eq "", "bad_url_src $command");

    clean_remote_file($dest_host, $dest_file);
}
push(@tests, "bad_url_src");

# Test #4: Bad URL: Do a 3rd party transfer of an unwritable location as the
# destination twice using URL caching.
# Success if program returns 1 and no core file is generated.
sub bad_url_dest
{
    my ($errors,$rc) = ("",0);

    my $command = "$test_exec -s $proto$source_host$source_file -d $proto$dest_host$dest_file/etc/no-such-file-here";
    $errors = run_command($command, 2);

    ok($errors eq "", "bad_url_dest $command");
}
push(@tests, "bad_url_dest");

# Test #5-45: Do a simple transfer of test-file to/from localhost twice,
# using caching, and aborting at each possible position. Note that not all
# aborts may be reached.
# Success if no core file is generated for all abort points. (we could use
# a stronger measure of success here)
sub abort_test
{
    my ($errors,$rc) = ("", 0);
    my ($abort_point) = shift;

    my $command = "$test_exec -a $abort_point -s $proto$source_host$source_file -d $proto$dest_host$dest_file";
    $errors = run_command($command, -2);

    ok($errors eq "", "abort_test $abort_point $command");
    
    clean_remote_file($dest_host, $dest_file);
}
for(my $i = 1; $i <= 43; $i++)
{
    push(@tests, "abort_test($i);");
}

# Test #46-86. Restart functionality: Do a simple transfer of test-file
# to/from localhost twice using URL caching, restarting at each
# plugin-possible point. Compare the resulting file with the real file.
# Success if program returns 0, files compare,
# and no core file is generated.
sub restart_test
{
    my ($errors,$rc) = ("",0);
    my ($restart_point) = shift;

    my $command = "$test_exec -r $restart_point -s $proto$source_host$source_file -d $proto$dest_host$dest_file";
    $errors = run_command($command, 0);
    if($errors eq "")
    {
        my ($output) = get_remote_file($dest_host, $dest_file);
        $errors = compare_local_files($local_copy, $output);
        unlink($output);
    }

    ok($errors eq "", "restart_test $restart_point $command");
    
    clean_remote_file($dest_host, $dest_file);
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
