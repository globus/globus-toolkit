#! /usr/bin/env perl
#
# Ping a valid and invalid gatekeeper contact.

use strict;
use POSIX;
use Test;
use IO::File;
use File::Path;

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
        my ($host, $uniq_id, $dropping_dir);
        $tag =~ m|https://([^:]+):\d+/(\d+/\d+)/|;
        $host = $1;
        $uniq_id = $2;
        $uniq_id =~ s|/|.|;
        sleep($timeout+5);


        $dropping_dir = "$ENV{HOME}/.globus/job/$host/$uniq_id";

        if (($mode eq 'no-commit-end') && ($save_state eq 'yes'))
        {
            if(! -r $dropping_dir)
            {
                $errors .= "Test should have left droppings";
            }
            else
            {
                rmtree([$dropping_dir]);
            }
        }
        else
        {
            if(-r $dropping_dir)
            {
                $errors .= "Test left unexpected droppings in the cache";
                rmtree([$dropping_dir]);
            }
        }
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
