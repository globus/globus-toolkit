#! /usr/bin/env perl
#
use strict;
use POSIX;
use Test;

my $test_exec = 'globus-gram-client-register-callback-test';

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
my $testno=1;

sub register_callback_test
{
    my ($errors,$rc) = ("",0);
    my ($output);
    my ($contact, $test, $result) = @_;
    my $valgrind = "";

    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-globus_gram_client_register_callback_test_" . $testno++ . ".log";
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
        }
    }

    system("$valgrind $test_exec '$contact' $test >/dev/null");
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
push(@tests, "register_callback_test('$ENV{CONTACT_STRING}', 1, 0);");
push(@tests, "register_callback_test('$ENV{CONTACT_STRING}X', 1, 7);");
push(@tests, "register_callback_test('$ENV{CONTACT_STRING}', 2, 0);");
push(@tests, "register_callback_test('$ENV{CONTACT_STRING}', 3, 0);");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
