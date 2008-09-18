#! /usr/bin/env perl
#
use strict;
use POSIX;
use Test;

my $test_exec = './globus-gram-client-register-refresh-credentials-test';

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
my $valgrind = "";

if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-globus_gram_client_register_register_refresh_credentials_test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

sub refresh_creds_test
{
    my ($errors,$rc) = ("",0);
    my ($output);
    my ($contact) = shift;

    system("$valgrind $test_exec '$contact' >/dev/null");
    $rc = $?>> 8;
    if($rc != 0)
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
push(@tests, "refresh_creds_test('$ENV{CONTACT_STRING}');");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
