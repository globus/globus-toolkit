#! /usr/bin/env perl

use strict;
use POSIX;
use Test;

require "test-common.pl";

my @tests;
my @todo;
my $test_exec="./framework_test";

my $inline_finish;

#setup different driver combinations
my @drivers;
push(@drivers, "");
push(@drivers, "-D debug");
push(@drivers, "-D test_bounce_transform");
push(@drivers, "-D debug -D test_bounce_transform");
push(@drivers, "-D test_bounce_transform -D debug");
push(@drivers, "-D debug -D test_bounce_transform -D debug");
push(@drivers, "-D test_bounce_transform -D debug -D test_bounce_transform");

my $test_name="framework";
my $server_flag="-s";
sub basic_tests
{
    my $inline_finish="-i";

    for(my $i = 0; $i < 2; $i++)
    {
        foreach(@drivers)
        {
            my $d=$_;
            for(my $j = 0; $j < 2; $j++)
            {
                push(@tests, "$test_exec $test_name -w 4 -r 4 $inline_finish $d $server_flag");
                $server_flag="";
            }
        }
        $inline_finish="";
    }
}

&basic_tests();
my $cnt=0;
plan tests => scalar(@tests), todo => \@todo;
foreach(@tests)
{
    my $test_str="$test_name.$cnt";
    &run_test($_, $test_str);
    $cnt++;
}
