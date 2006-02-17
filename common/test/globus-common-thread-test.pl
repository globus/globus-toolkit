#!/usr/bin/env perl

#
# Portions of this file Copyright 1999-2005 University of Chicago
# Portions of this file Copyright 1999-2005 The University of Southern California.
#
# This file or a portion of this file is licensed under the
# terms of the Globus Toolkit Public License, found at
# http://www.globus.org/toolkit/download/license.html.
# If you redistribute this file, with or without
# modifications, you must include this notice in the file.
#


=pod

=head1 Tests for the globus common thread handling code

Tests to exercise the thread functionality of the globus
common library.

=cut

use strict;
use POSIX;
use Test;

my $test_prog = './globus_common_thread_test';

# Accomodate running tests on Windows platform - remove leading './'
if ("$^O" =~ /win32/i)
{
   $test_prog =~ s/(.\/)//;
}

my $diff = 'diff';
my @tests;
my @todo;

sub basic_func
{
   my ($errors,$rc) = ("",0);
   
   $rc = system("$test_prog 10 5 10 1>$test_prog.log.stdout 2>$test_prog.log.stderr") / 256;

   if($rc != 0)
   {
      $errors .= "Test exited with $rc. ";
   }

   if(-r 'core')
   {
      $errors .= "\n# Core file generated.";
   }
   
   $rc = system("$diff $test_prog.log.stdout $test_prog.stdout") / 256;
   
   if($rc != 0)
   {
      $errors .= "Test produced unexpected output, see $test_prog.log.stdout";
   }


   $rc = system("$diff $test_prog.log.stderr $test_prog.stderr") / 256;
   
   if($rc != 0)
   {
      $errors .= "Test produced unexpected output, see $test_prog.log.stderr";
   }

   if($errors eq "")
   {
      ok('success', 'success');
      
      if( -e "$test_prog.log.stdout" )
      {
	 unlink("$test_prog.log.stdout");
      }
      
      if( -e "$test_prog.log.stderr" )
      {
	 unlink("$test_prog.log.stderr");
      } 
   }
   else
   {
      ok($errors, 'success');
   }

}

sub sig_handler
{
   if( -e "$test_prog.log.stdout" )
   {
      unlink("$test_prog.log.stdout");
   }

   if( -e "$test_prog.log.stderr" )
   {
      unlink("$test_prog.log.stderr");
   }
}

$SIG{'INT'}  = 'sig_handler';
$SIG{'QUIT'} = 'sig_handler';
$SIG{'KILL'} = 'sig_handler';


push(@tests, "basic_func();");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
   eval "&$_";
}
