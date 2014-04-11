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
use Test::More;
use IO::File;

my $test_exec = "./two-phase-commit-test";
my $gass_cache = "globus-gass-cache";
my $globusrun = "globusrun";

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
    my ($contact, $mode, $timeout) = @_;
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
            "$valgrind $test_exec \"$contact\" $mode $timeout |");

    $tag = join('', <$fh>);
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


        if (($mode eq 'no-commit-end'))
        {
            my $cache_out = `$gass_cache -list -tag $tag | wc -l`;
            chomp($cache_out);
            if($cache_out eq "0")
            {
                $errors .= "Test should have left droppings";
            }
            else
            {
                print STDERR `$gass_cache -cleanup-tag $tag`;
                system("$globusrun", "-r", "$ENV{CONTACT_STRING}", "&(restart=$tag)");
            }
        }
        else
        {
            my $cache_out = `$gass_cache -list -tag $tag`;
            chomp($cache_out);
            if($cache_out ne '')
            {
                $errors .= "Test left unexpected droppings in the cache:\n"
                         . "$cache_out";
                print STDERR `$gass_cache -cleanup-tag $tag`;
            }
        }
    }

    ok($errors eq "", "$test_exec \"$contact\" $mode $timeout");
}

push(@tests,
        "two_phase_test('$ENV{CONTACT_STRING}','no-commit','1');");
push(@tests,
        "two_phase_test('$ENV{CONTACT_STRING}','no-commit-end','10');");
push(@tests,
        "two_phase_test('$ENV{CONTACT_STRING}','commit', '10');");
push(@tests,
        "two_phase_test('$ENV{CONTACT_STRING}','late-commit-end', '10');");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
