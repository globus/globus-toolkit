#! /usr/bin/env perl
#
# Try reading an url by passing in a bad data buffer

use strict;
use POSIX;
use Test;

my $test_exec = $ENV{GLOBUS_LOCATION} . '/test/' . 'globus-ftp-client-bad-buffer-test';

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my @tests;
my @todo;

# Test 1: Bad buffer test
# Success if the transfer fails with exit code 2
sub bad_buffer
{
    my ($errors,$rc) = ("",0);
    my ($output);

    unlink('core');

    system("$test_exec >/dev/null 2>/dev/null");
    $rc = $?>> 8;
    if($rc != 2)
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
push(@tests, "bad_buffer");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
