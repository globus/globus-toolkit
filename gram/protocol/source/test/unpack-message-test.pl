#! /usr/bin/perl
#

use warnings;
use strict;

my $test_exec = './unpack-message-test';

sub test
{
    my ($errors,$rc) = ("",0);
    my $output;
    my $valgrind = '';

    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-unpack-message-test.log";
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
        }
    }


    system("$valgrind $test_exec");

}

test();
