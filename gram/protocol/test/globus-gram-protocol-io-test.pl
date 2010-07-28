#! /usr/bin/perl
#

use warnings;
use strict;
use POSIX;
use Test;

my $test_exec = './globus-gram-protocol-io-test';

my @tests;
my @todo;

sub test
{
    my ($errors,$rc) = ("",0);
    my ($args, $expected_rc) = @_;
    my $valgrind = '';

    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-globus_gram_protocol_io_test-$args.log";
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
        }
    }

    system("$valgrind $test_exec $args >/dev/null 2>/dev/null");
    $rc = $?>> 8;
    if($rc != $expected_rc)
    {
        $errors .= "Test exited with $rc. ";
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        ok($errors, 'success');
    }
}

push(@tests, "test('', 0)");
push(@tests, "test('invalid_host', 12)");

plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
