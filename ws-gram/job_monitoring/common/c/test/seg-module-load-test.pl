#! /usr/bin/env perl

use Test;

my (@tests, @todo) = ();
my $test_exe = "seg-module-load-test";

sub module_load_test
{
    my $file = shift;

    system("./$test_exe");
}

push(@tests, 'module_load_test');

foreach(@tests) {
    eval "&$_";
}
