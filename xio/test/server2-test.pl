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

#setup different driver combinations
my @drivers;
push(@drivers, "");
push(@drivers, "-D debug");
push(@drivers, "-D bounce");
push(@drivers, "-D debug -D bounce");
push(@drivers, "-D bounce -D debug");
push(@drivers, "-D debug -D bounce -D verify");
push(@drivers, "-D bounce -D debug -D bounce");
push(@drivers, "-D null_pass -D bounce");

my $test_name="server2";
sub basic_tests
{
    my $inline_finish="-i";

    for(my $i = 0; $i < 2; $i++)
    {
        foreach(@drivers)
        {
            my $d=$_;
            push(@tests, "$test_name $inline_finish $d");
        }
        $inline_finish="";
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
        my $test_str="server2.$cnt";
        &run_test("$test_exec $_", $test_str);
        $cnt++;
    }
}
