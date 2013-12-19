#! /usr/bin/perl
#

use warnings;
use strict;
use POSIX;

my $test_exec = './create-extensions-test';

sub test
{
    my ($errors,$rc) = ("",0);
    my $output;
    my $valgrind = '';

    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-unpack-to-hash-test.log";
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
        }
    }


    system("$valgrind $test_exec");

}

test();
