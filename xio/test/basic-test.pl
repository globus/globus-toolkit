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

# setup different chunk sizes
my @chunk_sizes;
push(@chunk_sizes, "1024");
push(@chunk_sizes, "1924");
push(@chunk_sizes, "2048");

#setup different driver combinations
my @drivers;
push(@drivers, "");
push(@drivers, "-D debug");
push(@drivers, "-D test_bounce_transform");
push(@drivers, "-D debug -D test_bounce_transform");
push(@drivers, "-D test_bounce_transform -D debug");
push(@drivers, "-D debug -D test_bounce_transform -D debug");
push(@drivers, "-D test_bounce_transform -D debug -D test_bounce_transform");

sub basic_tests
{
    my $inline_finish="-i";
    my $delay="-d 1000";

    for(my $i = 0; $i < 2; $i++)
    {
        foreach(@drivers)
        {
            my $d=$_;
            foreach(@chunk_sizes)
            {
                my $c = $_;
                push(@tests, "$test_exec $test_name -w 1 -r 0 -c $c -b $buffer_size $inline_finish $d $delay");
                push(@tests, "$test_exec $test_name -w 0 -r 1 -c $c -b $buffer_size $inline_finish $d $delay");
                push(@tests, "$test_exec $test_name -w 0 -r 0 -c $c -b $buffer_size $inline_finish $d $delay");
                for(my $write_count = 1; $write_count <= 8; $write_count *= 2)
                {
                    for(my $read_count = 1; $read_count <= 8; $read_count *= 2)
                    {
                        push(@tests, "$test_exec $test_name -w $write_count -r $read_count -c $c -b $buffer_size $inline_finish $d $delay");
                    }
                }
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
