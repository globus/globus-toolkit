#!/usr/bin/perl

use strict;
use Test::More;
use Globus::Core::Paths;

my @tests;
my $dn = "/C=US/O=Globus Alliance/OU=User/CN=11783619ecc.2bcb9093";
my $username = (getpwuid($<))[0];
my $add = $Globus::Core::Paths::sbindir . "/grid-mapfile-add-entry";
my $delete = $Globus::Core::Paths::sbindir . "/grid-mapfile-delete-entry";
my $check = $Globus::Core::Paths::sbindir . "/grid-mapfile-check-consistency";
my $userok = "./gridmap-userok";


$ENV{GRIDMAP} = "gridmap.script-test";

sub add_test
{
    my $errors = 0;

    truncate($ENV{GRIDMAP}, 0);

    system("$add -dn '$dn' -ln $username > /dev/null");
    if ($? != 0)
    {
        print STDERR "Error adding \"$dn\" $username to gridmap\n";
        $errors = 1;
    }
    else
    {
        system("$check > /dev/null");
        if ($? != 0)
        {
            print STDERR "Error checking consistency of gridmap\n";
            $errors = 1;
        }

        system("$userok \"$dn\" $username");
        if ($? != 0)
        {
            print STDERR "Error resolving \"$dn\" to $username in gridmap\n";
            $errors = 1;
        }
    }
    ok($errors == 0, "add_test");
}

sub delete_empty_test
{
    my $errors = 0;

    truncate($ENV{GRIDMAP}, 0);

    system("$delete -dn '$dn' -ln $username > /dev/null 2>/dev/null");
    if ($? == 0)
    {
        print STDERR "Unexpected success deleting \"$dn\" $username from gridmap\n";
        $errors = 1;
    }
    ok($errors == 0, "delete_empty_test")
}

sub delete_entry_test
{
    my $errors = 0;

    truncate($ENV{GRIDMAP}, 0);

    system("$add -dn '$dn' -ln $username > /dev/null");
    if ($? != 0)
    {
        print STDERR "Error adding \"$dn\" $username to gridmap\n";
        $errors = 1;
        goto END;
    }
    system("$add -dn '$dn/2' -ln $username > /dev/null");
    if ($? != 0)
    {
        print STDERR "Error adding \"$dn/2\" $username to gridmap\n";
        $errors = 1;
        goto END;
    }
    system("$userok \"$dn\" $username");
    if (($? >> 8) != 0)
    {
        print STDERR "Error resolving \"$dn\" to $username in gridmap\n";
        $errors = 1;
        goto END;
    }
    system("$delete -dn '$dn' -ln $username > /dev/null");
    if ($? != 0)
    {
        print STDERR "Error deleting entry from gridmap\n";
        $errors = 1;
        goto END;
    }
    system("$check > /dev/null");
    if ($? != 0)
    {
        print STDERR "Error checking consistency of gridmap\n";
        $errors = 1;
        goto END;
    }
    system("$userok \"$dn\" $username > /dev/null 2> /dev/null");
    if (($? >> 8) == 0)
    {
        print STDERR "Unexpectedly resolved \"$dn\" to $username in gridmap\n";
        $errors = 1;
        goto END;
    }
END:
    ok($errors == 0, "delete_entry_test");
}


push(@tests, "add_test", "delete_empty_test", "delete_entry_test");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests);

# And run them all.
foreach (@tests)
{
   eval "&$_";
}
