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

my $type = 0;
if(@ARGV == 1)
{
    $type = 1;
}

my @tests;
my @todo;
my $test_exec="./http_header_test";
my $data_dir=$ENV{GLOBUS_LOCATION}."/share/globus_xio_test";

push(@tests, "$data_dir/headers");
push(@tests, "$data_dir/long-headers");
push(@tests, "$data_dir/multi-line-header");
push(@tests, "$data_dir/multi-headers");

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
    foreach(@tests)
    {
        my $result;
        chomp ($result = `$test_exec -s -f "$_" | $test_exec -c -f "$_"`);

        ok($result, 'Success');
    }
}
