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
push(@drivers, "");
push(@drivers, "-D debug");

my @failures;
push(@failures, "-F 1");
push(@failures, "-F 2");
push(@failures, "-F 5");
push(@failures, "-F 6");
push(@failures, "-F 7");
push(@failures, "-F 8");
push(@failures, "-F 9");
push(@failures, "-F 10");

sub failure_tests
{
    my $inline_finish="-i";

    for(my $i = 0; $i < 2; $i++)
    {
        foreach(@drivers)
        {
            my $d=$_;
            foreach(@failures)
            {
                my $f=$_;
                push(@tests, "$test_name $f -w 1 -r 1 -s $inline_finish $d");
            }
        }
        $inline_finish="";
    }
}

&failure_tests();
if($type == 1)
{
    foreach(@tests)
    {
        print "$_\n";
    }
}
else
{
    plan tests => scalar(@tests), todo => \@todo;
    my $cnt=0;
    foreach(@tests)
    {
        my $test_str="fail_test.$cnt";
        &run_test("$test_exec $_", $test_str);
        $cnt++;
    }
}
