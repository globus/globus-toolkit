#! /usr/bin/env perl

use strict;
use POSIX;
use Test;

require "test-common.pl";

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
push(@drivers, "-D test_bounce_transform");

sub basic_tests
{
    my $inline_finish="-i";
    my $server_flag="-s";

    for(my $i = 0; $i < 2; $i++)
    {
        foreach(@drivers)
        {
            my $d=$_;
            for(my $j = 0; $j < 10; $j++)
            {
                my $sd = time % 1000;
                push(@tests, "$test_exec $test_name -X $sd -w 32 -r 32 $inline_finish $d -W 524288 -R 524288");
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
    my $test_str="random.$cnt";
    &run_test($_, $test_str);
    $cnt++;
}
