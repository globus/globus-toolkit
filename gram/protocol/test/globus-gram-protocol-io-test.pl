#! /usr/bin/env perl
#

use strict;
use POSIX;
use Test;

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
    my ($args, $expected_rc) = @_;

    unlink('core');

    system("$test_exec $args >/dev/null 2>/dev/null");
    $rc = $?>> 8;
    if($rc != $expected_rc)
    {
        $errors .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
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
