#! /usr/bin/env perl
#
use strict;
use POSIX;
use Test;

my $test_exec = 'globus-gram-client-refresh-credentials-test';

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

sub refresh_creds_test
{
    my ($errors,$rc) = ("",0);
    my ($output);
    my ($contact) = shift;

    unlink('core');

    system("$test_exec '$contact' >/dev/null 2>/dev/null");
    $rc = $?>> 8;
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
push(@tests, "refresh_creds_test('$ENV{CONTACT_STRING}');");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
