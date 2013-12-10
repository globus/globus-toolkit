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
# Activate and deactivate the client library

use strict;
use POSIX;
use Test::More;

plan tests => 4;

my $test_exec = 'callback-contact-test';

testit(1);
testit(2);
testit(3);
testit(4);

sub testit
{
    my ($rc, $status);
    my $arg = $_[0];
    my $valgrind = "";
    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-globus_gram_client_contact_test.log";
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
        }
    }

    chomp($status = `$valgrind $test_exec $arg`);
    $rc = $?;
    ok($rc == 0, "$test_exec $arg");
}
