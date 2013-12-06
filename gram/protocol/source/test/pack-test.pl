#! /usr/bin/perl
#

use warnings;
use strict;
use POSIX;
use Test;

my $test_exec = './pack-test';

my @tests;
my @todo;

sub test
{
    my ($errors,$rc) = ("",0);
    my ($arg) = shift;
    my $output;
    my $valgrind = '';

    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-pack_test-$arg.log";
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
push(@tests, "test(3)");
push(@tests, "test(4)");
push(@tests, "test(5)");
push(@tests, "test(6)");

plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
