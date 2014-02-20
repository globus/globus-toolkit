#! /usr/bin/perl

# 
# Copyright 1999-2014 University of Chicago
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

# These tests use globus-url-copy with various security and concurrency options
require 5.8.0;

use strict;
use warnings;
use Test::More;
use Cwd;
use IPC::Open3;
use Symbol qw/gensym/;
use Getopt::Long;
use File::Temp qw/ tempfile tempdir /;
use File::Copy;
use File::Path qw/rmtree/;

srand(1);

my $subject = $ENV{FTP_TEST_SUBJECT};
my $server_cs = $ENV{FTP_TEST_CONTACT};

my @dc_opts;
if ($subject)
{
    push(@dc_opts, ["-nodcau", "-subject", $subject]);
    push(@dc_opts, ["-subject", $subject]);
    push(@dc_opts, ["-dcsafe", "-subject", $subject]);
    push(@dc_opts, ["-dcpriv", "-subject", $subject]);
}
else
{
    push(@dc_opts, []);
}

my @concur;
push(@concur, []);
for(my $i = 1; $i < 10; $i += 3)
{
    push(@concur, ["-cc", "$i"]);
}

my $work_dir = tempdir( CLEANUP => 1);
mkdir("$work_dir/GL");

my @chars=("A".."Z","a".."z","0".."9");
for (my $i = 0; $i < 64; $i++)
{
    my $fn = "";
    $fn .= $chars[rand(@chars)] for 1..8;
    my $fd;
    open($fd, ">$work_dir/GL/$fn");
    print $fd $chars[rand @chars] for 1..int(rand(4096));
}
my $src_url = "${server_cs}${work_dir}/GL/";
my $dst_url = "${server_cs}${work_dir}/GL2/";

my $test_count = 2 * scalar(@dc_opts) * scalar(@concur);
plan tests => $test_count;

SKIP: {
    skip "Missing URL or subject", $test_count unless($server_cs && $subject);
    my $i = 0;
    foreach my $dc_opt (@dc_opts)
    {
        foreach my $cc (@concur)
        {
            my ($infd, $outfd, $errfd);
            my ($out, $err);
            my ($pid, $rc);
            $errfd = gensym;

            $pid = open3($infd, $outfd, $errfd, "globus-url-copy",
                "-pp", @{$cc}, @{$dc_opt},
                "-cd", "-r", $src_url, $dst_url);
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

            ok($rc == 0, join(" ", "guc cc $i", @{$cc}, @{$dc_opt}[0..scalar(@$dc_opt)-3],
                ,"exits with 0"));

            $errfd = gensym;
            $pid = open3($infd, $outfd, $errfd, "diff", "-r",
                "$work_dir/GL", "$work_dir/GL2");
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

            ok($rc == 0 && !$out, join(" ", "guc pp-cc $i diff ", @{$cc}, @{$dc_opt}[0..scalar(@$dc_opt)-3]));
            rmtree("$work_dir/GL2");
            $i++;
        }
    }
}
exit(77) if ((!$server_cs) || (!$subject));
