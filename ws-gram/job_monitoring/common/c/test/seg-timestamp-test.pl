#! /usr/bin/env perl

use Test;

my (@tests, @todo) = ();
my $test_exe = "seg-timestamp-test";

sub timestamp_test
{
    my $file = shift;

    system("./$test_exe");
}

push(@tests, 'timestamp_test');

foreach(@tests) {
    eval "&$_";
}
