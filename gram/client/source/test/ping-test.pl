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

use strict;
use POSIX;
use Test::More;

my $test_exec = './ping-test';

if ($ENV{CONTACT_STRING} eq "")
{
    die "CONTACT_STRING not set";
}

my @tests;
my @todo;
my $caseno=1;

sub ping_test
{
    my ($errors,$rc) = ("",0);
    my ($output);
    my ($contact, $result) = @_;
    my $valgrind = "";

    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-globus_gram_client_ping_test_" . $caseno++ . ".log";
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
        }
    }

    system("$valgrind $test_exec '$contact' >/dev/null");
    $rc = $?>> 8;
    if($rc != $result)
    {
        $errors .= "Test exited with $rc. ";
    }
    ok($errors eq "", "ping_test $contact $result");
}
push(@tests, "ping_test('$ENV{CONTACT_STRING}', 0);");
push(@tests, "ping_test('$ENV{CONTACT_STRING}X', 7);");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
