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
my $test_name="cancel";


#setup different driver combinations
my @drivers;
push(@drivers, "");
push(@drivers, "-D debug");
push(@drivers, "-D bounce");
push(@drivers, "-D debug -D bounce");
push(@drivers, "-D debug -D bounce -D debug");

my @cancel_position;
push(@cancel_position, "O");
push(@cancel_position, "D");

sub basic_tests
{
        foreach(@drivers)
        {
            my $d=$_;
            foreach(@cancel_position)
            {
                my $t=$_;
                push(@tests, "$test_name -d 300000 -w 1 -r 0 $d $t");
                push(@tests, "$test_name -d 300000 -w 0 -r 1 $d $t");
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
