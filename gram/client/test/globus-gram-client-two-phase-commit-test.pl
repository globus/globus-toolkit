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
my $testno=1;

sub two_phase_test
{
    my ($errors,$rc) = ("",0);
    my ($output);
    my $cache_cmd;
    my ($contact, $mode, $timeout) = @_;
    my $tag;
    my $valgrind = "";

    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-globus_gram_client_two_phase_commit_test" . $testno++ . ".log";
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
        }
    }
    my $fh = new IO::File(
            "$valgrind $test_exec \"$contact\" $mode $timeout |");

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


        if (($mode eq 'no-commit-end'))
        {
            my $cache_out = `globus-gass-cache -list -tag $tag | wc -l`;
            chomp($cache_out);
            if($cache_out eq "0")
            {
                $errors .= "Test should have left droppings";
            }
            else
            {
                print STDERR `globus-gass-cache -cleanup-tag $tag`;
            }
        }
        else
        {
            my $cache_out = `globus-gass-cache -list -tag $tag | wc -l`;
            chomp($cache_out);
            if($cache_out ne "0")
            {
                $errors .= "Test left unexpected droppings in the cache";
                print STDERR `globus-gass-cache -cleanup-tag $tag`;
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
        "two_phase_test('$ENV{CONTACT_STRING}','no-commit','1');");
push(@tests,
        "two_phase_test('$ENV{CONTACT_STRING}','no-commit-end','10');");
push(@tests,
        "two_phase_test('$ENV{CONTACT_STRING}','commit', '10');");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "&$_";
}
