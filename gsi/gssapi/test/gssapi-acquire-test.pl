#!/usr/bin/env perl

use strict;
use POSIX;
use Test;
use Cwd qw(cwd);

my $test_prog = 'gssapi-acquire-test';

my $diff = 'diff';
my @tests;
my @todo;

sub basic_func
{
    my ($errors,$rc) = ("",0);
   
    $ENV{X509_CERT_DIR} = cwd();
    $ENV{X509_USER_PROXY} = "testcred.pem";

    $rc = system("./$test_prog >/dev/null 2>&1") / 256;

    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }

    if(-r 'core')
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
