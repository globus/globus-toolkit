#! /usr/bin/env perl

use strict;
use POSIX;
use Test;

require "test-common.pl";

my $type = 0;
if(@ARGV == 1)
{   
    $type = 1;
}

my @tests;
my @todo;
my $test_exec="./framework_test";

my @build_tests = qw(
            basic-test.pl
            close-barrier-test.pl
            failure-test.pl
            read-barrier-test.pl
            timeout-test.pl
            random-test.pl
            server-test.pl
            verify-test.pl
            );

my $filename="all_tests.txt";
unlink($filename);
foreach(@build_tests)
{
    my $cmd = "$_ P >> $filename";
    system($cmd);
}

push(@tests, "-D $filename");
push(@tests, "-A -D $filename");

my $cnt=0;
plan tests => scalar(@tests), todo => \@todo;
foreach(@tests)
{
    my $test_str="ALL.$cnt";
    &run_test("$test_exec $_", $test_str);
    $cnt++;
}
