#! /usr/bin/env perl
#

use strict;

my $test_exec = 'unpack-message-test';

my $gpath = $ENV{GLOBUS_LOCATION};

my ($errors,$rc) = ("",0);
my $output;
my @args = ("./$test_exec");
my @valgrind_args = ();

if (exists $ENV{VALGRIND})
{
    push(@valgrind_args, "valgrind");
    push(@valgrind_args, "--log-file=VALGRIND-$test_exec.log");
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        push(@valgrind_args, split(/\s+/, $ENV{VALGRIND_OPTIONS}));
    }
    unshift(@args, @valgrind_args);
}

system(@args);
