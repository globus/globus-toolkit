#! /usr/bin/env perl
#
# Ping a valid and invalid gatekeeper contact.

use strict;
use POSIX;
use Test;
use IO::File;

my $test_exec = './globus-gram-client-two-phase-commit-test';

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

sub two_phase_test
{
    my ($errors,$rc) = ("",0);
    my ($output);
    my $cache_cmd;
    my ($contact, $mode, $save_state, $timeout) = @_;
    my $tag;
    my $fh = new IO::File(
            "$test_exec \"$contact\" $mode $save_state $timeout 2>/dev/null|");

    $tag = join('', <$fh>);
    $fh->close();
    chomp($tag);

    $rc = $?>> 8;
    if ($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }
    if($tag eq '')
    {
        $errors .= "Didn't get a real job id from the test.\n";
    }
    else
    {
        sleep($timeout+5);
        $cache_cmd = "$gpath/bin/globus-gass-cache -list -t \"$tag\"";

        $fh = new IO::File("$cache_cmd|");
        $output = join('', <$fh>);
        $fh->close();
        chomp($output);

        if (($mode eq 'no-commit-end') && ($save_state eq 'yes'))
        {
            if($output eq "")
            {
                $errors .= "Test should have left droppings in the cache";
            }
        }
        else
        {
            if($output ne "")
            {
                $errors .= "Test left unexpected droppings in the cache";
            }
        }
        $cache_cmd = "$gpath/bin/globus-gass-cache -cleanup-tag -t \"$tag\"";
        system($cache_cmd . ">/dev/null 2>/dev/null");
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

push(@tests,
        "two_phase_test('$ENV{CONTACT_STRING}','no-commit','no','1');");
push(@tests,
        "two_phase_test('$ENV{CONTACT_STRING}','no-commit','yes','1');");
push(@tests,
        "two_phase_test('$ENV{CONTACT_STRING}','no-commit-end','no','10');");
push(@tests,
        "two_phase_test('$ENV{CONTACT_STRING}','no-commit-end','yes','10');");
push(@tests,
        "two_phase_test('$ENV{CONTACT_STRING}','commit', 'no','10');");
push(@tests,
        "two_phase_test('$ENV{CONTACT_STRING}','commit', 'yes','10');");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
