#! /usr/bin/perl
#

use warnings;
use strict;
use Test;

my $test_exec = './error-test';

my @tests;
my @todo;

sub test
{
    my ($errors,$rc) = ("",0);
    my $output;
    my $valgrind = '';
    my $arg = shift;

    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-error_test-$arg.log";
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
        }
    }

    chomp($output = `$valgrind $test_exec $arg`);
    $rc = $?>> 8;
    if($rc != 0)
    {
        $output .= "Test exited with $rc. ";
    }

    ok($output, 'ok');
}

push(@tests, "test(1)");
push(@tests, "test(2)");

plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
