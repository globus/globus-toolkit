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
my $test_name="timeout";


#setup different driver combinations
my @drivers;
push(@drivers, "");
push(@drivers, "-D debug");
push(@drivers, "-D bounce");
push(@drivers, "-D debug -D bounce -D debug");

my @timeout_position;
push(@timeout_position, "O");
push(@timeout_position, "D");
push(@timeout_position, "C");

my @timeout_vals;
push(@timeout_vals, "300000");
push(@timeout_vals, "600000");
push(@timeout_vals, "900000");

sub basic_tests
{
    my $inline_finish="-i";
    my $noto;

    foreach(@timeout_vals)
    {
        $noto=$_;
        foreach(@drivers)
        {
            my $d=$_;
            foreach(@timeout_position)
            {
                my $t=$_;
                push(@tests, "$test_name -d $noto -w 1 -r 0 $d $t");
                push(@tests, "$test_name -d $noto -w 0 -r 1 $d $t");
            }
        }
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
        my $test_str="$test_name.$cnt";
        &run_test("$test_exec $_", $test_str);
        $cnt++;
    }
}
