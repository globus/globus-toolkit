#! /usr/bin/env perl

use strict;
use POSIX;
use Test;

my $test_exec = 'globus-gram-client-register-cancel-test';

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}
if ($ENV{CONTACT_STRING} eq "")
{
    die "CONTACT_STRING not set";
}

@INC = (@INC, "$gpath/lib/perl");

my @tests;
my @todo;

sub cancel_test
{
    my ($errors,$rc) = ("",0);
    my ($output);
    my ($contact, $result) = @_;

    unlink('core');

    system("$test_exec '$contact' >/dev/null 2>/dev/null");
    $rc = $?>> 8;
    if($rc != $result)
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
push(@tests, "cancel_test('$ENV{CONTACT_STRING}', 0);");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
