#! /usr/bin/env perl
#
# Copyright 1999-2010 University of Chicago
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
# Ping a valid and invalid gatekeeper contact.

my $prefix;
my $exec_prefix;
my $sbindir;
my $bindir;
my $includedir;
my $datarootdir;
my $datadir;
my $libdir;
my $libexecdir;
my $sysconfdir;
my $sharedstatedir;
my $localstatedir;
my $perlmoduledir;

BEGIN
{
    $prefix = '@prefix@';
    if ($ENV{GLOBUS_LOCATION})
    {
        $prefix = $ENV{GLOBUS_LOCATION};
    }
    $exec_prefix="@exec_prefix@";
    $sbindir="@sbindir@";
    $bindir="@bindir@";
    $includedir="@includedir@";
    $datarootdir="@datarootdir@";
    $datadir="@datadir@";
    $libdir="@libdir@";
    $libexecdir="@libexecdir@";
    $sysconfdir="@sysconfdir@";
    $sharedstatedir="@sharedstatedir@";
    $localstatedir="@localstatedir@";
    $perlmoduledir="@perlmoduledir@";

    unshift(@INC, $perlmoduledir);
}

use strict;
use Test::More;
use IO::File;
use Globus::Core::Paths;

my $test_exec = './failed-job-two-phase-commit';

if ($ENV{CONTACT_STRING} eq "")
{
    die "CONTACT_STRING not set";
}

my @tests;
my @todo;
my $testno=1;

sub two_phase_test
{
    my ($errors,$rc) = ("",0);
    my ($output);
    my $cache_cmd;
    my ($contact, $timeout) = @_;
    my $tag;
    my $valgrind = "";

    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-globus_gram_client_two_phase_commit_test" . $testno++ . ".log";
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
        }
    }
    my $fh = new IO::File(
            "$valgrind $test_exec \"$contact\" $timeout |");

    $tag = <$fh>;
    sleep($timeout+5);
    $fh->close();
    chomp($tag);

    $rc = $?>> 8;
    if ($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }
    if($tag eq '')
    {
        $errors .= "Didn't get a real job id from the test.\n";
    }
    else
    {
        sleep($timeout+5);

        my $cache_out = `$Globus::Core::Paths::bindir/globus-gass-cache -list -tag $tag`;
        chomp($cache_out);
        if($cache_out ne '')
        {
            $errors .= "Test left unexpected droppings in the cache:\n"
                     . "$cache_out";
            print STDERR `$Globus::Core::Paths::bindir/globus-gass-cache -cleanup-tag $tag`;
        }
    }

    ok($errors eq "", "$test_exec \"$contact\" $timeout");
}

push(@tests,
        "two_phase_test('$ENV{CONTACT_STRING}','1');");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
