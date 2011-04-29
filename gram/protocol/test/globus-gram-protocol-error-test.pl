#! /usr/bin/env perl
#

use strict;

my $test_exec = './globus-gram-protocol-error-test';

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my @tests;
my @todo;

sub test
{
    my ($errors,$rc) = ("",0);
    my $output;
    my $valgrind = '';
    my $arg = shift;
    my $testname = $test_exec;
    my @args = ($test_exec, $arg);

    $testname =~ s|^\./||;

    if (exists $ENV{VALGRIND})
    {
        my @valgrind_args = ();
        push (@valgrind_args, 'valgrind');
        push (@valgrind_args, "--log-file=VALGRIND-$testname.log");
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            push(@valgrind_args, split(/\s+/, $ENV{VALGRIND_OPTIONS}));
        }
        unshift(@args, @valgrind_args);
    }

    system(@args);
    return $?>> 8;
}

push(@tests, "test(1)");
push(@tests, "test(2)");
printf "1..%d\n", scalar(@tests);

foreach (@tests)
{
    eval "&$_";
}
