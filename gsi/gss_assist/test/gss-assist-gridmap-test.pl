#!/usr/bin/env perl

use strict;
use Test;
use Cwd;

my @tests;
my @todo;

my $test_prog = './gss-assist-gridmap';

$ENV{GRIDMAP} = "grid-mapfile";

sub basic_func
{
    my ($errors,$rc) = ("",0);
    
   unlink('core');

   $rc = system("$test_prog") / 256;

   if($rc != 0)
   {
      $errors .= "Test exited with $rc. ";
   }

   if(-r 'core')
   {
      ok("Core file generated.", 'ok');
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
