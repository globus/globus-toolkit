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
# Activate and deactivate the client library

use strict;
use File::Path;
use Test::Simple;

my @tests;
my @todo;

sub cleanup
{
    my $testarray = $_[0];
    my $testprog;
    my @cmd;
    my $rc;
    if (scalar(@{$testarray}) == 2)
    {
        $testprog = $testarray->[1];
        $testprog = "globus-connect-multiuser-".$testarray->[1]."-cleanup";
    }
    else
    {
        $testprog = "globus-connect-multiuser-cleanup";
    }
    $cmd[0] = $testprog;
    $cmd[1] = "-c";
    $cmd[1] = $testarray->[0];
    $rc = system(@cmd);

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
    return $rc;
}

sub run_test
{
    my $testarray = $_[0];
    my $testprog;
    my @cmd;
    my $rc;
    
    if (scalar(@{$testarray}) == 2)
    {
        $testprog = $testarray->[1];
        $testprog = "globus-connect-multiuser-".$testarray->[1]."-setup";
    }
    else
    {
        $testprog = "globus-connect-multiuser-setup";
    }
    $cmd[0] = $testprog;
    $cmd[1] = "-c";
    $cmd[2] = $testarray->[0];
    $rc = system(@cmd);

    $rc |= cleanup(@_);

    ok($rc == 0, $rc);
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

plan tests => scalar(@tests);
foreach (@tests)
{
    run_test($_);
}
