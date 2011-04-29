#! /usr/bin/env perl
#

use strict;
use Test::More;

my $test_exec = './globus-gram-protocol-io-test';

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
    my ($arg, $expected_rc) = @_;
    my @args=($test_exec);
    my @valgrind_args = ();
    my $testname = $test_exec;

    $testname =~ s|^./||;

    if ($arg ne '')
    {
        push(@args, $arg);
        $testname .= "-$arg";
    }

    if (exists $ENV{VALGRIND})
    {
        @valgrind_args = ('valgrind', "--log-file=VALGRIND-$testname.log");
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            push(@valgrind_args, split(/\s+/, $ENV{VALGRIND_OPTIONS}));
        }
    }
    @args = (@valgrind_args, @args);

    system(@args);
    $rc = $?>> 8;
    ok ($rc eq $expected_rc, $testname);
}

push(@tests, "test('', 0)");
push(@tests, "test('invalid_host', 12)");

plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
