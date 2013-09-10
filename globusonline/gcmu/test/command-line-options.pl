#! /usr/bin/perl
#
# Copyright 1999-2013 University of Chicago
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

END {$?=0}

use strict;
use File::Path;
use File::Temp;
use IPC::Open3;
use Test::More;

my $tempdir = mkdtemp("/tmp/XXXXXXX");

END
{
    File::Path::rmtree($tempdir);
}

my @tests=(
    {
        NAME => "globus-connect-multiuser-setup-c",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-setup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-setup-clong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-setup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-setup-v",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-setup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-setup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-setup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-setup-r",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-setup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-setup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-setup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-setup-s",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-setup",
                "-c", "command-line-options.conf",
                "-s"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-setup-slong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-setup",
                "-c", "command-line-options.conf",
                "--reset-endpoint"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-setup-h",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-setup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-setup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-setup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-setup-cbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-setup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-setup-rbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-setup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-setup-extrabad",
        COMMAND_LINE => [
            "globus-connect-multiuser-setup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-cleanup-c",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-cleanup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-cleanup-clong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-cleanup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-cleanup-v",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-cleanup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-cleanup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-cleanup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-cleanup-r",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-cleanup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-cleanup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-cleanup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-cleanup-d",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-cleanup",
                "-c", "command-line-options.conf",
                "-d"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-cleanup-dlong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-cleanup",
                "-c", "command-line-options.conf",
                "--delete-endpoint"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-cleanup-h",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-cleanup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-cleanup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-cleanup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-cleanup-cbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-cleanup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-cleanup-rbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-cleanup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-cleanup-extrabad",
        COMMAND_LINE => [
            "globus-connect-multiuser-cleanup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-id-setup-c",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-id-setup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-setup-clong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-id-setup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-setup-v",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-id-setup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-setup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-id-setup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-setup-r",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-id-setup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-setup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-id-setup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-setup-h",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-id-setup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-setup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-id-setup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-setup-cbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-id-setup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-id-setup-rbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-id-setup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-id-setup-extrabad",
        COMMAND_LINE => [
            "globus-connect-multiuser-id-setup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-id-cleanup-c",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-id-cleanup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-cleanup-clong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-id-cleanup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-cleanup-v",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-id-cleanup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-cleanup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-id-cleanup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-cleanup-r",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-id-cleanup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-cleanup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-id-cleanup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-cleanup-h",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-id-cleanup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-cleanup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-id-cleanup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-id-cleanup-cbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-id-cleanup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-id-cleanup-rbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-id-cleanup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-id-cleanup-extrabad",
        COMMAND_LINE => [
            "globus-connect-multiuser-id-cleanup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-io-setup-c",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-io-setup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-setup-clong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-io-setup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-setup-v",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-io-setup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-setup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-io-setup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-setup-r",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-io-setup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-setup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-io-setup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-setup-s",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-io-setup",
                "-c", "command-line-options.conf",
                "-s"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-setup-slong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-io-setup",
                "-c", "command-line-options.conf",
                "--reset-endpoint"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-setup-h",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-io-setup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-setup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-io-setup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-setup-cbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-io-setup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-io-setup-rbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-io-setup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-io-setup-extrabad",
        COMMAND_LINE => [
            "globus-connect-multiuser-io-setup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-io-cleanup-c",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-io-cleanup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-cleanup-clong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-io-cleanup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-cleanup-v",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-io-cleanup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-cleanup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-io-cleanup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-cleanup-r",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-io-cleanup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-cleanup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-io-cleanup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-cleanup-d",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-io-cleanup",
                "-c", "command-line-options.conf",
                "-d"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-cleanup-dlong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-io-cleanup",
                "-c", "command-line-options.conf",
                "--delete-endpoint"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-cleanup-h",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-io-cleanup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-cleanup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-io-cleanup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-io-cleanup-cbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-io-cleanup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-io-cleanup-rbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-io-cleanup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-io-cleanup-extrabad",
        COMMAND_LINE => [
            "globus-connect-multiuser-io-cleanup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-web-setup-c",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-web-setup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-setup-clong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-web-setup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-setup-v",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-web-setup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-setup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-web-setup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-setup-r",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-web-setup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-setup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-web-setup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-setup-h",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-web-setup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-setup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-web-setup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-setup-cbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-web-setup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-web-setup-rbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-web-setup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-web-setup-extrabad",
        COMMAND_LINE => [
            "globus-connect-multiuser-web-setup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-web-cleanup-c",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-web-cleanup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-cleanup-clong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-web-cleanup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-cleanup-v",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-web-cleanup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-cleanup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-web-cleanup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-cleanup-r",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-web-cleanup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-cleanup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-multiuser-web-cleanup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-cleanup-h",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-web-cleanup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-cleanup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-multiuser-web-cleanup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-multiuser-web-cleanup-cbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-web-cleanup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-web-cleanup-rbad",
        COMMAND_LINE => [
            "globus-connect-multiuser-web-cleanup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-multiuser-web-cleanup-extrabad",
        COMMAND_LINE => [
            "globus-connect-multiuser-web-cleanup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    }
);

plan tests => scalar(@tests);

foreach my $test (@tests)
{
    my $test_name = $test->{NAME};
    my @test_commandline = @{$test->{COMMAND_LINE}};
    my $test_expectation = $test->{RESULT};

    my ($pid, $in, $out, $err);
    $pid = open3($in, $out, $err, @test_commandline);
    close($in);
    waitpid($pid, 0);
    my $rc = $? >> 8;
    print STDERR join("", <$out>);
    print STDERR join("", <$err>);
    ok(($rc == 0) == $test_expectation, $test_name);
}
exit(0);
