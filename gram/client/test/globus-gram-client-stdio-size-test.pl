#! /usr/bin/env perl
#
# send stdio_size signal

use strict;
use POSIX;
use Test;

my $test_exec = './globus-gram-client-stdio-size-test';

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

sub size_test
{
    my ($contact) = @_;
    my $rc;
    my $cmdline;
    my $errors='';

    $cmdline = "$test_exec '$contact' ";
    system("$cmdline >/dev/null 2>/dev/null");
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
push(@tests, "size_test('$ENV{CONTACT_STRING}')");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
