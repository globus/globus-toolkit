#! /usr/bin/env perl

use strict;
use POSIX;
use Test;

require "test-common.pl";

my @tests;
my @todo;
my $test_exec="./framework_test";
my $test_name="read_barrier";

my $inline_finish;
my $buffer_size=2048;
my $c;

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

sub read_barrier
{
#  print out read barrier tests
    my $inline_finish="-i";
    for(my $i = 0; $i < 2; $i++)
    {
        foreach(@chunk_sizes)
        {
            $c = $_;
            foreach(@drivers)
            {
                for(my $read_count = 1; $read_count <= 8; $read_count *= 2)
                {
                    push(@tests, "$test_exec $test_name -r $read_count -c $c -b $buffer_size $inline_finish $_");
                }
            }
        }
        $inline_finish="";
    }
}

&read_barrier();
plan tests => scalar(@tests), todo => \@todo;
my $cnt=0;
foreach(@tests)
{
    my $test_str="$test_name.$cnt";
    &run_test($_, $test_str);
    $cnt++;
}
