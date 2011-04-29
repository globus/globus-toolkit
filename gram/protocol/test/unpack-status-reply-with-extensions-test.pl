#! /usr/bin/env perl
#

use strict;

my $test_exec = 'unpack-status-reply-with-extensions-test';

my @args = ("./$test_exec");

if (exists $ENV{VALGRIND})
{
    my @valgrind_args = ();
    push(@valgrind_args, "valgrind");
    push(@valgrind_args, "--log-file=VALGRIND-$test_exec.log");
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        push(@valgrind_args, split(/\s+/, $ENV{VALGRIND_OPTIONS}));
    }
    unshift(@args, @valgrind_args);
}

system(@args);
exit($? >> 8);
