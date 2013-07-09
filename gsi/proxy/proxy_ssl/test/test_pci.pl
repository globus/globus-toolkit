#!/usr/bin/perl

=pod

=head1 Tests for the globus gsi proxy_ssl code

Tests that exercise the functionality of creating an
ASN1 DER encoded PROXYCERTINFO extension to be placed
in an X509 certificate.

=cut

use strict;
use File::Compare;
use Test::More;

my $test_prog = 'test_pci';

my @tests;
my @todo;
my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-$test_prog.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

sub basic_func
{
   my ($errors,$rc) = ("",0);

   my $test_index = shift;
   my $options = shift;
   my $testname = shift;

   my $rc1 = system("$valgrind $test_prog $options -out $test_prog.norm$test_index.der 1>$test_prog.log1.stdout") / 256;
   my $rc2 = system("./$test_prog -in $test_prog.norm$test_index.der -out $test_prog.log$test_index.der 1> $test_prog.log2.stdout") / 256;

   ok($rc1 == 0 && $rc2 == 0 &&
        File::Compare::compare("$test_prog.log$test_index.der",
                               "$test_prog.norm$test_index.der") == 0 &&
        File::Compare::compare("$test_prog.log1.stdout",
                "$test_prog.log2.stdout") == 0,
        $testname);

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


push(@tests, "basic_func(1, \"-path 10 -rest POLICYLANGUAGE POLICY\", \"path10-policy\");");
push(@tests, "basic_func(2, \"-path 10\", \"path10\");");
push(@tests, "basic_func(3, \"-path 0 -rest POLICYLANGUAGE POLICY\", \"path0-policy\");");
push(@tests, "basic_func(4, \"-rest POLICYLANGUAGE POLICY\", \"policy\");");
push(@tests, "basic_func(5, \"-out test_pci5.der\", \"default\");");


# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
   eval "&$_";
}
