#!/usr/bin/env perl

use strict;
use Test;
use Globus::Testing::Utilities;

my $test_prog = 'gssapi-thread-test';

my $diff = 'diff';
my @tests;
my @todo;
Globus::Testing::Utilities::testcred_setup
    || die "Unable to set up test credentials\n";


my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-gssapi_thread_test.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

sub basic_func
{
    my ($errors,$rc) = ("",0);
   
    $rc = system("$valgrind ./$test_prog >/dev/null 2>&1") / 256;

    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }

    if($rc & 128)
    {
        $errors .= "\n# Core file generated.";
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

push(@tests, "basic_func();");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
    eval "&$_";
}
