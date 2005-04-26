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
my $test_exec="./http_throughput_test";
my $data_dir=$ENV{GLOBUS_LOCATION}."/share/globus_xio_test";

                    my $client_args = '-c ';
                    my $server_args = '-s ';

                    push (@tests, [$client_args, $server_args]);


if($type == 1)
{
    foreach (@ARGV) {
        print "$test_exec $tests[$_]->[1] | $test_exec $tests[$_]->[0]\n";
    }
}
else
{
    plan tests => scalar(@tests), todo => \@todo;
    foreach(@tests)
    {
        my $result;
        chomp ($result = `$test_exec $_->[1]  | $test_exec $_->[0]`);

        ok($result, 'Success');
    }
}
