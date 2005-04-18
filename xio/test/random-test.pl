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

my $buffer_size=2048;
my $test_name="framework";

#setup different driver combinations
my @drivers;
push(@drivers, "");
push(@drivers, "-D debug");
push(@drivers, "-D bounce");

sub basic_tests
{
    my $inline_finish="-i";
    my $server_flag="-s";

    foreach(@drivers)
    {
        my $d=$_;
        for(my $j = 0; $j < 10; $j++)
        {
            my $sd = time % 1000;
            push(@tests, "$test_name -X $sd -w 32 -r 32 $d -W 524288 -R 524288");
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
        my $test_str="random.$cnt";
        &run_test("$test_exec $_", $test_str);
        $cnt++;
    }
}
