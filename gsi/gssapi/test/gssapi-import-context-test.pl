#!/usr/bin/env perl

use strict;
use POSIX;
use Test;
use Globus::Testing::Utilities;

my $test_prog = 'gssapi-import-context-test';
Globus::Testing::Utilities::testcred_setup
    || die "Unable to set up test credentials\n";

sub basic_func
{
    my ($errors,$rc) = ("",0);
   
    $rc = system("./$test_prog");

    if ($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }

    if ($rc & 128)
    {
        $errors .= "\n# Core file generated.";
    }
   
    if ($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        ok($errors, 'success');
    }

}

my @tests = ("basic_func();");
my @todo = ();

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
    eval "&$_";
}
