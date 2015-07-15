#!/usr/bin/perl

use strict;

my $test_prog = './gss-assist-gridmap';

my ($valgrind) = ('');
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-gss_assist_gridmap_test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

my $GRIDMAP;
my $dn = '/DC=org/DC=doegrids/OU=People/UserID=328453245/EMAIL=john@doe.com/EmailAddress=john@doe.com';
my $local = 'jdoe';

if ($ENV{TEST_GRIDMAP_DIR})
{
    $GRIDMAP = "$ENV{TEST_GRIDMAP_DIR}/grid-mapfile";
}
else
{
    $GRIDMAP = "grid-mapfile";
}

system("$valgrind $test_prog -g \"$GRIDMAP\" -d \"$dn\" -l \"$local\"");
exit($? >> 8)
