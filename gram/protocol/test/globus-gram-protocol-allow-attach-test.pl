#! /usr/bin/env perl
#

use strict;
use POSIX;
use Test;

my $test_exec = './globus-gram-protocol-allow-attach-test';

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

    unlink('core');

    chomp($output = `$test_exec $arg`);
    $rc = $?>> 8;
    if($rc != 0)
    {
        $output .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $output .= "\n# Core file generated.";
    }

    ok($output, 'ok');
}

push(@tests, "test(1)");
push(@tests, "test(2)");
push(@tests, "test(3)");
push(@tests, "test(4)");

plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
