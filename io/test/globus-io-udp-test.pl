#!/usr/bin/env perl

=head1 Tests for the globus IO authorization modes

=cut

use strict;
use POSIX;
use POSIX "sys_wait_h";
use Test;
use Cwd;

my @tests;
my @todo;

my $server_prog = './globus_io_udp_test_server';
my $client_prog = './globus_io_udp_test_client';

sub basic_func
{
   my ($errors,$rc) = ("",0);
   my $port;
   my $server_pid;
   my $client_pid;

   unlink('core');

   $server_pid = open(SERVER, "$server_prog|");

   if($server_pid == -1)
   {
       $errors .= "Unable to start server";
       return;
   }

   $port = <SERVER>;
   $port = <SERVER>;
   $port = <SERVER>;
   $port =~ s/Binding to //;
   chomp($port);

   $client_pid = open(CLIENT, "$client_prog -h localhost -p $port|");

   if($client_pid == -1)
   {
       $errors .= "Unable to start client";
       return;
   }
   
   waitpid($server_pid,0);

   if($? != 0)
   {
       $errors .= "Server exited abnormally. \n The following output was generated:\n";
       while(<SERVER>)
       {
           $errors .= $_;
       }
   }

   waitpid($client_pid,0);

   if($? != 0)
   {
       $errors .= "Client exited abnormally. \n The following output was generated:\n";
       while(<CLIENT>)
       {
           $errors .= $_;
       }
   }
   
   close(CLIENT);
   close(SERVER);

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
