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
use IPC::Open3;
use Test::More;

my @tests;
my @todo;

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

sub cleanup
{
    my $testarray = $_[0];
    my $testprog;
    if (scalar(@{$testarray}) == 2)
    {
        $testprog = $testarray->[1];
        $testprog = "globus-connect-multiuser-".$testarray->[1]."-cleanup";
    }
    else
    {
        $testprog = "globus-connect-multiuser-cleanup";
    }
    my @cmd = ($testprog, "-c", $testarray->[0]);
    my $rc = diagsystem(@cmd);

    # Just to make sure that doesn't fail
    foreach my $f (</etc/gridftp.d/globus-connect*>)
    {
        unlink($f);
    }
    foreach my $f (</etc/myproxy.d/globus-connect*>)
    {
        unlink($f);
    }
    File::Path::rmtree("/var/lib/globus-connect-multiuser");
    unlink("/var/lib/myproxy-oauth/myproxy-oauth.db");
    return $rc;
}

sub run_test
{
    my $testarray = $_[0];
    my $testprog;
    if (scalar(@{$testarray}) == 2)
    {
        $testprog = $testarray->[1];
        $testprog = "globus-connect-multiuser-".$testarray->[1]."-setup";
    }
    else
    {
        $testprog = "globus-connect-multiuser-setup";
    }
    my @cmd = ($testprog, "-c", $testarray->[0]);
    my $rc = diagsystem(@cmd);

    $rc |= cleanup(@_);

    ok($rc == 0, $testarray->[0]);
}

# Test Case #1:
# single server running all services
push(@tests, ["single-server-all-services.conf"]);

# Test Case #2:
# single server running all services with sharing enabled
push(@tests, [ "single-server-all-services-sharing.conf" ]);

# Test Case #3:
# i/o server using cilogon
push(@tests, ["io-cilogon.conf", "io"]);

# Test Case #4:
# i/o server using cilogon & sharing
push(@tests, ["io-cilogon-sharing.conf", 'io']);

plan tests=>scalar(@tests);
foreach (@tests)
{
    run_test($_);
}
# vim: filetype=perl:
