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

my $inline_finish;
my $buffer_size=2048;
my $test_name="framework";

#setup different driver combinations
my @drivers;
push(@drivers, "-D verify");
push(@drivers, "-D verify -D debug");
push(@drivers, "-D debug -D verify");
push(@drivers, "-D verify -D bounce");
push(@drivers, "-D bounce -D verify");
push(@drivers, "-D debug -D bounce -D verify");
push(@drivers, "-D verify -D debug -D bounce");

sub basic_tests
{
    my $inline_finish="-i";
    my $s="";

    for(my $j = 0; $j < 2; $j++)
    {
        for(my $i = 0; $i < 2; $i++)
        {
            foreach(@drivers)
            {
                my $d=$_;
                push(@tests, "$test_name -s -w 1 -r 0 $inline_finish $d");
                push(@tests, "$test_name -s -w 0 -r 1 $inline_finish $d");
                push(@tests, "$test_name -s -w 0 -r 0 $inline_finish $d");
            }
            $inline_finish="";
        }
        $s="-s";
    }
}

&basic_tests();

if($type == 1)
{
    foreach(@tests)
    {
        print "$_\n";
    }
}
else
{
    my $cnt=0;
    plan tests => scalar(@tests), todo => \@todo;
    foreach(@tests)
    {
        my $test_str="verify.$cnt";
        &run_test("$test_exec $_", $test_str);
        $cnt++;
    }
}
