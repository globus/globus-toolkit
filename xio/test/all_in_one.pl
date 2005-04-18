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

my @build_tests = qw(
            basic-test.pl
            close-barrier-test.pl
            failure-test.pl
            read-barrier-test.pl
            timeout-test.pl
            random-test.pl
            server-test.pl
            verify-test.pl
            );

my $filename="all_tests.txt";
unlink($filename);
foreach(@build_tests)
{
    my $cmd = "$_ P >> $filename";
    system($cmd);
}

push(@tests, "-D $filename");
push(@tests, "-A -D $filename");

my $cnt=0;
plan tests => scalar(@tests), todo => \@todo;
foreach(@tests)
{
    my $test_str="ALL.$cnt";
    &run_test("$test_exec $_", $test_str);
    $cnt++;
}
