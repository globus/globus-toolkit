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
my $test_exec="./http_post_test";
my $data_dir=$ENV{GLOBUS_LOCATION}."/share/globus_xio_test";

my @test_files = ("$data_dir/headers",
             "$data_dir/long-headers",
             "$data_dir/large-file");
my @versions = ('', 'HTTP/1.0', 'HTTP/1.1');
my @buffers = (0, 256, 512, 1024, 1024*1024);

for my $file (@test_files) {
    for my $client_version (@versions) {
        for my $server_version (@versions) {
            for my $client_buffer (@buffers) {
                for my $server_buffer (@buffers) {
                    my $client_args = '-c ';
                    my $server_args = '-s ';

                    $client_args .= "-f \"$file\" ";
                    $server_args .= "-f \"$file\" ";

                    if ($client_version ne '') {
                        $client_args .= "-v $client_version ";
                    }
                    if ($server_version ne '') {
                        $server_args .= "-v $server_version ";
                    }
                    if ($client_buffer != 0) {
                        $client_args .= "-b $client_buffer ";
                    }
                    if ($server_buffer != 0) {
                        $server_args .= "-b $server_buffer ";
                    }

                    push (@tests, [$client_args, $server_args]);
                }
            }
        }
    }
}


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
