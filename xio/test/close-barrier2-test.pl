#! /usr/bin/env perl

#
# Portions of this file Copyright 1999-2005 University of Chicago
# Portions of this file Copyright 1999-2005 The University of Southern California.
#
# This file or a portion of this file is licensed under the
# terms of the Globus Toolkit Public License, found at
# http://www.globus.org/toolkit/download/license.html.
# If you redistribute this file, with or without
# modifications, you must include this notice in the file.
#


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
my $test_name="close2_barrier";

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
push(@drivers, "-D bounce");
push(@drivers, "-D debug -D bounce");
push(@drivers, "-D bounce -D debug");
#push(@drivers, "-D null -D debug");
push(@drivers, "-D debug -D bounce -D debug");
#push(@drivers, "-D bounce -D null -D bounce");

sub close_barrier2
{
    my $inline_finish="-i";

    for(my $i = 0; $i < 2; $i++)
    {
        foreach(@chunk_sizes)
        {
            my $c = $_;
            foreach(@drivers)
            {
                push(@tests, "$test_name -w 1 -r 0 -c $c -b $buffer_size $inline_finish $_");
                push(@tests, "$test_name -w 0 -r 1 -c $c -b $buffer_size $inline_finish $_");
                for(my $write_count = 1; $write_count <= 16; $write_count *= 4)
                {
                    for(my $read_count = 1; $read_count <= 16; $read_count *= 4)
                    {
                        push(@tests, "$test_name -w $write_count -r $read_count -c $c -b $buffer_size $inline_finish $_");
                    }
                }
            }
        }
        $inline_finish="";
    }
}

&close_barrier2();
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
        my $test_str="$test_name.$cnt";
        &run_test("$test_exec $_", $test_str);
        $cnt++;
    }
}
