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

# These tests use globus-url-copy with various security protection options.
# using a tcp port range
require 5.8.0;

use strict;
use warnings;
use Test::More;
use Cwd;
use IPC::Open3;
use Symbol qw/gensym/;
use Getopt::Long;
use File::Temp qw/ tempfile tempdir /;
use File::Compare;

my $subject = $ENV{FTP_TEST_SUBJECT};
my $server_cs = $ENV{FTP_TEST_CONTACT};

my @dc_opts = (
    ["-nodcau", "-subject", $subject],
    ["-subject", $subject],
    ["-dcsafe", "-subject", $subject],
    ["-dcpriv", "-subject", $subject]);
    
my $work_dir = tempdir( CLEANUP => 1);

my @chars=("A".."Z","a".."z","0".."9");
my $fd;
open ($fd, ">$work_dir/src.data");
print $fd $chars[rand @chars] for 1..10240*1024;
close($fd);

my $test_count = 2 * scalar(@dc_opts);
plan tests => $test_count;

SKIP: {
    skip "Missing URL or subject", $test_count unless($server_cs && $subject);

    my $src_url = "${server_cs}${work_dir}/src.data";
    my $dst_url = "${server_cs}${work_dir}/dst.data";

    foreach my $dc_opt (@dc_opts)
    {
        my ($infd, $outfd, $errfd);
        my ($out, $err);
        my ($pid, $rc);
        $errfd = gensym;

        $pid = open3($infd, $outfd, $errfd, "globus-url-copy",
            '-fsstack', 'file', '-dcstack', 'gsi,tcp', '-stripe',
            @{$dc_opt},
            $src_url, $dst_url);
        close($infd);

        waitpid($pid, 0);
        $rc = $?;

        {
            local($/);
            $out = <$outfd> if $outfd;
            $err = <$errfd> if $errfd;

            $out =~ s/^/# /mg if $out;
            $err =~ s/^/# /mg if $err;

            print STDERR "# stdout:\n$out" if $out;
            print STDERR "# stderr:\n$err" if $err;
        }

        ok($rc == 0, join(" ", "guc stack", @{$dc_opt}[0..scalar(@$dc_opt)-3],
            ,"exits with 0"));

        ok(compare("$work_dir/src.data", "$work_dir/dst.data") == 0,
            "guc-stack data compare");
        unlink("$work_dir/dst.data") if (-f "$work_dir/dst.data");
    }
}
exit(77) if ((!$server_cs) || (!$subject));
