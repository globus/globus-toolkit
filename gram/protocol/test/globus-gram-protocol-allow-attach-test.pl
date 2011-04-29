#! /usr/bin/env perl
#

use strict;

my $test_exec = './globus-gram-protocol-allow-attach-test';

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my @tests;

sub test
{
    my ($arg) = shift;
    my $output;
    my @args = ($test_exec, $arg);
    my @valgrind_args = ();

    if (exists $ENV{VALGRIND})
    {
        push(@valgrind_args, 'valgrind', "--log-file=VALGRIND-globus_gram_protocol_allow_attach_test-$arg.log");
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            push(@valgrind_args, split(/s+/, $ENV{VALGRIND_OPTIONS}));
        }
    }
    @args = (@valgrind_args, @args);

    system(@args);
    return $?>>8;
}

push(@tests, "test(1)");
push(@tests, "test(2)");
push(@tests, "test(3)");
push(@tests, "test(4)");

printf "1..%d\n", scalar(@tests);
foreach (@tests)
{
    eval "&$_";
}
