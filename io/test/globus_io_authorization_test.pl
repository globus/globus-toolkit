#!/usr/bin/env perl

=head1 Tests for the globus IO authorization modes

=cut

use strict;
use POSIX;
use Test;

my @tests;
my @todo;

my $test_prog = 'globus_io_authorization_test';

my $diff = 'diff';

sub basic_func
{
   my ($errors,$rc) = ("",0);
   my $args = shift;
   my $result;
   
   unlink('core');
   chomp($result = `$test_prog $args`);

   if($rc != 0)
   {
      $errors .= "Test exited with $rc. ";
   }

   if(-r 'core')
   {
      ok("Core file generated.", 'ok');
   }
   else
   {
       ok($result, 'ok');
   }
}

my $id = `$ENV{GLOBUS_LOCATION}/bin/grid-cert-info -subject`;
$id =~ s/^\s+//;
chomp($id);

push(@tests, "basic_func('self');");
push(@tests, "basic_func('identity \"$id\"')");
push(@tests, "basic_func('callback');");
push(@tests, "basic_func('-callback');");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
   eval "&$_";
}
