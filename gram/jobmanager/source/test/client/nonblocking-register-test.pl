#! /usr/bin/perl
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
use strict;
use POSIX;
use Test;

my $test_exec = './nonblocking-register-test';

if ($ENV{CONTACT_STRING} eq "")
{
    die "CONTACT_STRING not set";
}

my @tests;
my @todo;
my $caseno=1;

sub register_callback_test
{
    my ($errors,$rc) = ("",0);
    my ($output);
    my ($contact, $test, $result) = @_;
    my $valgrind = "";

    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-nonblocking_register_test_" . $caseno++ . ".log";
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
        }
    }

    system("$valgrind $test_exec '$contact' $test >/dev/null");
    $rc = $?>> 8;
    if($rc != $result)
    {
        $errors .= "Test exited with $rc. ";
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        ok($errors, 'success');
    }
}
push(@tests, "register_callback_test('$ENV{CONTACT_STRING}', 1, 0);");
push(@tests, "register_callback_test('$ENV{CONTACT_STRING}X', 1, 7);");
push(@tests, "register_callback_test('$ENV{CONTACT_STRING}', 2, 0);");
push(@tests, "register_callback_test('$ENV{CONTACT_STRING}', 3, 0);");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
