#! /usr/bin/env perl
#
# Ping a valid and invalid gatekeeper contact.

use strict;
use POSIX;
use Test;

my $test_exec = './globus-gram-client-register-ping-test';

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

sub register_test
{
    my ($contact, $credential, $result) = @_;
    my $rc;
    my $cmdline;
    my $errors='';

    if($contact ne '')
    {

        $cmdline = "$test_exec '$contact' ";
        if($credential ne '')
        {
            $cmdline .= "'$credential'";
        }

        system("$cmdline >/dev/null 2>/dev/null");
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
    else
    {
        skip($contact eq '', "Can't tweak contact", 0);
    }
}
push(@tests, "register_test('$ENV{CONTACT_STRING}', '', 0);");
push(@tests, "register_test('$ENV{CONTACT_STRING}', '$ENV{X509_USER_PROXY}', 0);");

my $bad_contact;
if($ENV{CONTACT_STRING} =~ m/:(.*):/)
{
    my $replacement = $1 . "/bogus";

    $bad_contact=$ENV{CONTACT_STRING};
    $bad_contact=~s/:(.*):/:$replacement:/;
}

push(@tests, "register_test('$bad_contact', '', 93);");
push(@tests, "register_test('$bad_contact', '$ENV{X509_USER_PROXY}', 93);");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
