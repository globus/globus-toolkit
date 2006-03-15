#!/usr/bin/env perl

# 
# Copyright 1999-2006 University of Chicago
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 


=head1 Tests for the globus IO authorization modes

=cut

use strict;
use POSIX;
use Test;

my @tests;
my @todo;

my $test_prog = './globus_io_authorization_test';

my $diff = 'diff';

sub basic_func
{
   my ($errors,$rc) = ("",0);
   my $args = shift;
   my $result;
   my $expect_failure = shift;
   
   unlink('core');
   my $command = "$test_prog $args";
   #print "Running: $command\n";
   chomp($result = `$test_prog $args`);

   if($rc != 0 && !$expect_failure)
   {
      $errors .= "Test exited with $rc. ";
   }

   if(-r 'core')
   {
      ok("Core file generated.", 'ok');
   }
   else
   {
       if(!$expect_failure)
       {
           ok($result, 'ok');
       }
       else
       {
           ok($result, "an authorization operation failed");
       }
   }
}

$ENV{X509_CERT_DIR} = getcwd();
$ENV{X509_USER_PROXY} = "testcred.pem";
$ENV{X509_USER_CERT} = "testcred.pem";
$ENV{X509_USER_KEY} = "testcred.pem";

my $identity = `grid-proxy-info -identity`;
chomp($identity);

push(@tests, "basic_func('self',0);");
push(@tests, "basic_func('identity \"$identity\"',0)");
push(@tests, "basic_func('identity \"/CN=bad DN\"',1)");
push(@tests, "basic_func('callback',0);");
push(@tests, "basic_func('-callback',1);");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
   eval "&$_";
}
