#! /usr/bin/env perl
#
# Activate and deactivate the client library

use strict;
use POSIX;
use Test;

my $test_exec = 'globus-gram-client-callback-contact-test';

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my @tests;
my @todo;

sub testit
{
    my ($rc, $status);
    my $arg = $_[0];
    my $valgrind = "";
    if (exists $ENV{VALGRIND})
    {
        $valgrind = "valgrind --log-file=VALGRIND-globus_gram_client_contact_test.log";
        if (exists $ENV{VALGRIND_OPTIONS})
        {
            $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
        }
    }

    chomp($status = `$valgrind $test_exec $arg`);
    $rc = $?;
    if($rc != 0)
    {
	ok("test returned $rc", 'ok');
    }
    else
    {
	ok($status, 'ok');
    }
}
push(@tests, "testit(1);");
push(@tests, "testit(2);");
push(@tests, "testit(3);");
push(@tests, "testit(4);");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

foreach (@tests)
{
    eval "$_";
}
