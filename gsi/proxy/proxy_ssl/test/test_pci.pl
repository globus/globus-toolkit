#!/usr/bin/perl

=pod

=head1 Tests for the globus gsi proxy_ssl code

Tests that exercise the functionality of creating an
ASN1 DER encoded PROXYCERTINFO extension to be placed
in an X509 certificate.

=cut

use strict;
use POSIX;
use Test;

my $test_prog = 'test_pci';

my $diff = 'diff';
my @tests;
my @todo;

sub basic_func
{
   my ($errors,$rc) = ("",0);

   my $options = shift;

   print "$test_prog $options 1>$test_prog.log1.stdout 2>$test_prog.log1.stderr\n\n";

   my $rc1 = system("$test_prog $options 1>$test_prog.log1.stdout 2>$test_prog.log1.stderr") / 256;
   my $rc2 = system("$test_prog -in $test_prog.log1.stdout 1>$test_prog.log2.stdout 2>$test_prog.log2.stderr") / 256;
   my $rc1 = 0;
   my $rc2 = 0;

   if($rc1 != 0 || $rc2 != 0)
   {
      $errors .= "Test exited with $rc. ";
   }

   if(-r 'core')
   {
      $errors .= "\n# Core file generated.";
   }
   
   $rc1 = system("$diff $test_prog.log1.stderr $test_prog.log2.stderr") / 256;

   if($rc1 != 0)
   {
      $errors .= "Test produced unexpected output, see $test_prog.log1.stderr\n\n";
   }

   $rc2 = system("$diff $test_prog.log1.stdout $test_prog.log2.stdout 1>/dev/null 2>/dev/null") / 256;
   
   if($rc2 != 0)
   {
      $errors .= "Test produced unexpected output, see $test_prog.log2.stdout\n\n";
   }

   if($errors eq "")
   {
      ok('success', 'success');
      
      if( -e "$test_prog.log2.stdout" || -e "$test_prog.log1.stdout")
      {
	 unlink("$test_prog.log2.stdout");
         unlink("$test_prog.log1.stdout");
      }
      
      if( -e "$test_prog.log2.stderr" || -e "$test_prog.log1.stderr")
      {
	 unlink("$test_prog.log2.stderr");
         unlink("$test_prog.log1.stderr");
      } 
   }
   else
   {
      ok($errors, 'success');
   }

}

sub sig_handler
{
    if( -e "$test_prog.log2.stdout" || -e "$test_prog.log1.stdout")
    {
        unlink("$test_prog.log2.stdout");
        unlink("$test_prog.log1.stdout");
    }
    
    if( -e "$test_prog.log2.stderr" || -e "$test_prog.log1.stderr")
    {
        unlink("$test_prog.log2.stderr");
        unlink("$test_prog.log1.stderr");
    }
}

$SIG{'INT'}  = 'sig_handler';
$SIG{'QUIT'} = 'sig_handler';
$SIG{'KILL'} = 'sig_handler';


push(@tests, "basic_func(\"-pc 1 -path 10 -group GROUPNAME 1 -rest POLICYLANGUAGE POLICY\");");
push(@tests, "basic_func(\"-pc 1 -path 10 -group GROUPNAME 0\");");
push(@tests, "basic_func(\"-pc 0 -path 0 -rest POLICYLANGUAGE POLICY -version 10\");");
push(@tests, "basic_func(\"-pc 0 -group GROUPNAME 1 -rest POLICYLANGUAGE POLICY\");");
push(@tests, "basic_func(\"-pc 1\");");


# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
   eval "&$_";
}
