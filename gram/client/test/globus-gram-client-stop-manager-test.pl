#! /usr/bin/env perl
#
# Ping a valid and invalid gatekeeper contact.

use strict;
use POSIX;
use Test;

my $test_exec = './globus-gram-client-stop-manager-test';

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

sub status_test
{
    my ($errors,$rc) = ("",0);
    my ($output);
    my ($contact, $arg, $result) = @_;

    system("$test_exec '$contact' $arg >/dev/null 2>/dev/null");
    $rc = $?>> 8;
    if($rc != $result)
    {
        $errors .= "Test exited with $rc. ";
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
push(@tests, "status_test('$ENV{CONTACT_STRING}', 1, 0);");
push(@tests, "status_test('$ENV{CONTACT_STRING}', 2, 0);");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
