#! /usr/bin/env perl

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
