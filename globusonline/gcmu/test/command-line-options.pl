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

sub diagsystem(@)
{
    my @cmd = @_;
    my ($pid, $in, $out, $err);
    my ($outdata, $errdata);
    $pid = open3($in, $out, $err, @cmd);
    close($in);
    local($/);
    $outdata = <$out>;
    $errdata = <$err>;
    diag("$cmd[0] stdout: $outdata") if ($outdata);
    diag("$cmd[0] stderr: $errdata") if ($errdata);
    waitpid($pid, 0);
    return $?;
}

my @tests=(
    {
        NAME => "globus-connect-server-setup-c",
        COMMAND_LINE => 
            [ "globus-connect-server-setup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-setup-clong",
        COMMAND_LINE => 
            [ "globus-connect-server-setup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-setup-v",
        COMMAND_LINE =>
            [ "globus-connect-server-setup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-setup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-server-setup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-setup-r",
        COMMAND_LINE => 
            [ "globus-connect-server-setup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-setup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-server-setup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-setup-s",
        COMMAND_LINE => 
            [ "globus-connect-server-setup",
                "-c", "command-line-options.conf",
                "-s"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-setup-slong",
        COMMAND_LINE => 
            [ "globus-connect-server-setup",
                "-c", "command-line-options.conf",
                "--reset-endpoint"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-setup-h",
        COMMAND_LINE =>
            [ "globus-connect-server-setup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-setup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-server-setup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-setup-cbad",
        COMMAND_LINE => [
            "globus-connect-server-setup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-setup-rbad",
        COMMAND_LINE => [
            "globus-connect-server-setup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-setup-extrabad",
        COMMAND_LINE => [
            "globus-connect-server-setup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-cleanup-c",
        COMMAND_LINE => 
            [ "globus-connect-server-cleanup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-cleanup-clong",
        COMMAND_LINE => 
            [ "globus-connect-server-cleanup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-cleanup-v",
        COMMAND_LINE =>
            [ "globus-connect-server-cleanup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-cleanup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-server-cleanup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-cleanup-r",
        COMMAND_LINE => 
            [ "globus-connect-server-cleanup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-cleanup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-server-cleanup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-cleanup-d",
        COMMAND_LINE => 
            [ "globus-connect-server-cleanup",
                "-c", "command-line-options.conf",
                "-d"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-cleanup-dlong",
        COMMAND_LINE => 
            [ "globus-connect-server-cleanup",
                "-c", "command-line-options.conf",
                "--delete-endpoint"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-cleanup-h",
        COMMAND_LINE =>
            [ "globus-connect-server-cleanup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-cleanup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-server-cleanup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-cleanup-cbad",
        COMMAND_LINE => [
            "globus-connect-server-cleanup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-cleanup-rbad",
        COMMAND_LINE => [
            "globus-connect-server-cleanup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-cleanup-extrabad",
        COMMAND_LINE => [
            "globus-connect-server-cleanup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-id-setup-c",
        COMMAND_LINE => 
            [ "globus-connect-server-id-setup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-setup-clong",
        COMMAND_LINE => 
            [ "globus-connect-server-id-setup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-setup-v",
        COMMAND_LINE =>
            [ "globus-connect-server-id-setup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-setup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-server-id-setup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-setup-r",
        COMMAND_LINE => 
            [ "globus-connect-server-id-setup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-setup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-server-id-setup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-setup-h",
        COMMAND_LINE =>
            [ "globus-connect-server-id-setup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-setup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-server-id-setup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-setup-cbad",
        COMMAND_LINE => [
            "globus-connect-server-id-setup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-id-setup-rbad",
        COMMAND_LINE => [
            "globus-connect-server-id-setup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-id-setup-extrabad",
        COMMAND_LINE => [
            "globus-connect-server-id-setup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-id-cleanup-c",
        COMMAND_LINE => 
            [ "globus-connect-server-id-cleanup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-cleanup-clong",
        COMMAND_LINE => 
            [ "globus-connect-server-id-cleanup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-cleanup-v",
        COMMAND_LINE =>
            [ "globus-connect-server-id-cleanup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-cleanup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-server-id-cleanup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-cleanup-r",
        COMMAND_LINE => 
            [ "globus-connect-server-id-cleanup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-cleanup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-server-id-cleanup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-cleanup-h",
        COMMAND_LINE =>
            [ "globus-connect-server-id-cleanup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-cleanup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-server-id-cleanup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-id-cleanup-cbad",
        COMMAND_LINE => [
            "globus-connect-server-id-cleanup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-id-cleanup-rbad",
        COMMAND_LINE => [
            "globus-connect-server-id-cleanup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-id-cleanup-extrabad",
        COMMAND_LINE => [
            "globus-connect-server-id-cleanup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-io-setup-c",
        COMMAND_LINE => 
            [ "globus-connect-server-io-setup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-setup-clong",
        COMMAND_LINE => 
            [ "globus-connect-server-io-setup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-setup-v",
        COMMAND_LINE =>
            [ "globus-connect-server-io-setup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-setup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-server-io-setup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-setup-r",
        COMMAND_LINE => 
            [ "globus-connect-server-io-setup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-setup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-server-io-setup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-setup-s",
        COMMAND_LINE => 
            [ "globus-connect-server-io-setup",
                "-c", "command-line-options.conf",
                "-s"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-setup-slong",
        COMMAND_LINE => 
            [ "globus-connect-server-io-setup",
                "-c", "command-line-options.conf",
                "--reset-endpoint"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-setup-h",
        COMMAND_LINE =>
            [ "globus-connect-server-io-setup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-setup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-server-io-setup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-setup-cbad",
        COMMAND_LINE => [
            "globus-connect-server-io-setup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-io-setup-rbad",
        COMMAND_LINE => [
            "globus-connect-server-io-setup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-io-setup-extrabad",
        COMMAND_LINE => [
            "globus-connect-server-io-setup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-io-cleanup-c",
        COMMAND_LINE => 
            [ "globus-connect-server-io-cleanup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-cleanup-clong",
        COMMAND_LINE => 
            [ "globus-connect-server-io-cleanup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-cleanup-v",
        COMMAND_LINE =>
            [ "globus-connect-server-io-cleanup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-cleanup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-server-io-cleanup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-cleanup-r",
        COMMAND_LINE => 
            [ "globus-connect-server-io-cleanup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-cleanup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-server-io-cleanup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-cleanup-d",
        COMMAND_LINE => 
            [ "globus-connect-server-io-cleanup",
                "-c", "command-line-options.conf",
                "-d"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-cleanup-dlong",
        COMMAND_LINE => 
            [ "globus-connect-server-io-cleanup",
                "-c", "command-line-options.conf",
                "--delete-endpoint"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-cleanup-h",
        COMMAND_LINE =>
            [ "globus-connect-server-io-cleanup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-cleanup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-server-io-cleanup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-io-cleanup-cbad",
        COMMAND_LINE => [
            "globus-connect-server-io-cleanup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-io-cleanup-rbad",
        COMMAND_LINE => [
            "globus-connect-server-io-cleanup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-io-cleanup-extrabad",
        COMMAND_LINE => [
            "globus-connect-server-io-cleanup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-web-setup-c",
        COMMAND_LINE => 
            [ "globus-connect-server-web-setup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-setup-clong",
        COMMAND_LINE => 
            [ "globus-connect-server-web-setup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-setup-v",
        COMMAND_LINE =>
            [ "globus-connect-server-web-setup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-setup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-server-web-setup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-setup-r",
        COMMAND_LINE => 
            [ "globus-connect-server-web-setup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-setup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-server-web-setup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-setup-h",
        COMMAND_LINE =>
            [ "globus-connect-server-web-setup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-setup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-server-web-setup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-setup-cbad",
        COMMAND_LINE => [
            "globus-connect-server-web-setup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-web-setup-rbad",
        COMMAND_LINE => [
            "globus-connect-server-web-setup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-web-setup-extrabad",
        COMMAND_LINE => [
            "globus-connect-server-web-setup",
            "bogus-additional-arg"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-web-cleanup-c",
        COMMAND_LINE => 
            [ "globus-connect-server-web-cleanup",
                "-c", "command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-cleanup-clong",
        COMMAND_LINE => 
            [ "globus-connect-server-web-cleanup",
                "--config-file=command-line-options.conf"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-cleanup-v",
        COMMAND_LINE =>
            [ "globus-connect-server-web-cleanup",
                "-c", "command-line-options.conf",
                "-v"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-cleanup-vlong",
        COMMAND_LINE =>
            [ "globus-connect-server-web-cleanup",
                "-c", "command-line-options.conf",
                "--verbose"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-cleanup-r",
        COMMAND_LINE => 
            [ "globus-connect-server-web-cleanup",
                "-c", "command-line-options.conf",
                "-r", $tempdir
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-cleanup-rlong",
        COMMAND_LINE => 
            [ "globus-connect-server-web-cleanup",
                "-c", "command-line-options.conf",
                "--root=$tempdir"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-cleanup-h",
        COMMAND_LINE =>
            [ "globus-connect-server-web-cleanup",
                "-h"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-cleanup-hlong",
        COMMAND_LINE =>
            [ "globus-connect-server-web-cleanup",
                "--help"
            ],
        RESULT => 1
    },
    {
        NAME => "globus-connect-server-web-cleanup-cbad",
        COMMAND_LINE => [
            "globus-connect-server-web-cleanup",
            "-c", "command-line-options-nonexistant.conf"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-web-cleanup-rbad",
        COMMAND_LINE => [
            "globus-connect-server-web-cleanup",
            "-r", "/etc/group"
        ],
        RESULT => 0
    },
    {
        NAME => "globus-connect-server-web-cleanup-extrabad",
        COMMAND_LINE => [
            "globus-connect-server-web-cleanup",
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
    my $rc = diagsystem(@test_commandline);
    ok(($rc == 0) == $test_expectation, $test_name);
}
exit(0);
