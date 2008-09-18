#! /usr/bin/env perl
#

use strict;
use POSIX;
use Test;

my $test_exec = './globus-gram-protocol-pack-test';

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
    my ($arg) = shift;
    my $output;
    my $valgrind = '';

    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-globus_gram_protocol_pack_test-$arg.log";
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
