#! /usr/bin/env perl
#
# Extremely basic data structure creation/destroy test. No transfers
# are done here. Sanity check activation/deactivation code, and make
# sure handle con/destructors work.

use strict;
use POSIX;
use Test;

my $test_exec = $ENV{GLOBUS_LOCATION} . '/test/' . 'globus-ftp-client-create-destroy-test';
my @tests;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

sub create_destroy
{
    my ($errors,$rc) = ("",0);

    unlink('core');

    $rc = system("$test_exec >/dev/null 2>/dev/null") / 256;
    if($rc != 0)
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
push(@tests, "create_destroy");

plan tests => scalar(@tests);

foreach (@tests)
{
    eval "&$_";
}
