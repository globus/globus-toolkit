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


=head1 Tests for the globus IO authorization modes

=cut

use strict;
use POSIX;
use POSIX "sys_wait_h";
use Test;

my @tests;
my @todo;

my $server_prog = './globus_io_tcp_test_server';
my $client_prog = './globus_io_tcp_test_client';

$ENV{X509_CERT_DIR} = getcwd();
$ENV{X509_USER_CERT} = "testcred.pem";
$ENV{X509_USER_KEY} = "testcred.pem";
$ENV{X509_USER_PROXY} = "testcred.pem";

my $identity = `grid-proxy-info -identity`;

chomp($identity);

sub basic_func
{
   my ($errors,$rc) = ("",0);
   my $server_args = shift;
   my $client_args = shift;
   my $expect_failure = shift;
   my $sec_env = shift;
   my $result;
   my $server_pid;
   my $client_pid;
   my $port;

   unlink('core');

   if($sec_env == 0)
   {
       $ENV{X509_CERT_DIR} = getcwd();
       $ENV{X509_USER_CERT} = "testcred.pem";
       $ENV{X509_USER_KEY} = "testcred.pem";
   }
   elsif($sec_env == 1)
   {
       $ENV{X509_CERT_DIR} = "";
       $ENV{X509_USER_KEY} = "testcred.pem";       
       $ENV{X509_USER_CERT} = "testcred.pem";       
   }
   elsif($sec_env == 2)
   {
       $ENV{X509_CERT_DIR} = getcwd();
       $ENV{X509_USER_CERT} = "";       
       $ENV{X509_USER_KEY} = "";       
       $ENV{X509_USER_PROXY} = "";       
   }
   
   my $command = "$server_prog $server_args |";
   #print "Running server: $command\n";
   $server_pid = open(SERVER, $command);

   if($server_pid == -1)
   {
       $errors .= "Unable to start server";
       return;
   }

   $port = <SERVER>;
   chomp($port);
   $port =~ s/listening on port //;

   $command = "$client_prog -h localhost -p $port $client_args |";
   #print "Running client: $command\n";
   $client_pid = open(CLIENT, $command);

   if($client_pid == -1)
   {
       $errors .= "Unable to start client";
       return;
   }
   
   waitpid($client_pid,0);

   if($? != 0)
   {
       $errors .= "Client exited abnormally. \n The following output was generated:\n";
       while(<CLIENT>)
       {
           $errors .= $_;
       }
       kill(9, $server_pid);
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

   close(CLIENT);
   close(SERVER);

   if(-r 'core')
   {
      ok("Core file generated.", 'ok');
   }

   if($errors eq "" || $expect_failure)
   {
       ok('success', 'success');
   }
   else
   {
       ok($errors, 'success');
   }
}



push(@tests, "basic_func(\"\",\"\",0,0);");
push(@tests, "basic_func(\"\",\"\",1,1);");
push(@tests, "basic_func(\"\",\"\",1,2);");
push(@tests, "basic_func(\"-g\",\"-g\",0,0);");
push(@tests, "basic_func(\"-g\",\"-g\",1,1);");
push(@tests, "basic_func(\"-g\",\"-g\",1,2);");
push(@tests, "basic_func(\"\",\"-g\",1,0);");
push(@tests, "basic_func(\"-s\",\"-s\",0,0);");
push(@tests, "basic_func(\"-s\",\"-s\",1,1);");
push(@tests, "basic_func(\"-s\",\"-s\",1,2);");
push(@tests, "basic_func(\"-s\",\"\",1,0);");
push(@tests, "basic_func(\"\",\"-s\",1,0);");
push(@tests, "basic_func(\"-c\",\"-c\",0,0);");
push(@tests, "basic_func(\"-c\",\"-c\",1,1);");
push(@tests, "basic_func(\"-c\",\"-c\",1,2);");
push(@tests, "basic_func(\"-c\",\"\",1,0);");
push(@tests, "basic_func(\"\",\"-c\",1,0);");
push(@tests, "basic_func(\"\",\"-H\",1,0);");
push(@tests, "basic_func(\"-g\",\"-H -g\",1,0);");
push(@tests, "basic_func(\"-s\",\"-H -s\",1,0);");
push(@tests, "basic_func(\"-c\",\"-H -c\",1,0);");
push(@tests, "basic_func(\"-c\",\"-i \'$identity\' -c\",0,0);");
push(@tests, "basic_func(\"-i \'$identity\' -c\",\"-c\",0,0);");
push(@tests, "basic_func(\"-c\",\"-i \'/CN=bogus\' -c\",1,0);");
push(@tests, "basic_func(\"-i \'/CN=bogus\' -c\",\"-c\",1,0);");
push(@tests, "basic_func(\"\",\"-d\",0,0);");
push(@tests, "basic_func(\"\",\"-D\",0,0);");
push(@tests, "basic_func(\"-g\",\"-d -g\",0,0);");
push(@tests, "basic_func(\"-g\",\"-D -g\",0,0);");
push(@tests, "basic_func(\"-s\",\"-d -s\",1,0);");
push(@tests, "basic_func(\"-s\",\"-D -s\",1,0);");
push(@tests, "basic_func(\"-c\",\"-d -c\",0,0);");
push(@tests, "basic_func(\"-c\",\"-D -c\",0,0);");
push(@tests, "basic_func(\"-v\",\"-v\",0,0);");
push(@tests, "basic_func(\"-v -g\",\"-v -g\",0,0);");
push(@tests, "basic_func(\"-v -s\",\"-v -s\",0,0);");
push(@tests, "basic_func(\"-v -c\",\"-v -c\",0,0);");
push(@tests, "basic_func(\"-i \'<anonymous>\'\",\"-a -i\'$identity\'\",0,0);");
push(@tests, "basic_func(\"\",\"-a -i\'$identity\'\",1,0);");
push(@tests, "basic_func(\"-b\",\"-b\",0,0);");
push(@tests, "basic_func(\"-b -g\",\"-b -g\",0,0);");
push(@tests, "basic_func(\"-b -s\",\"-b -s\",1,0);");
push(@tests, "basic_func(\"-b -c\",\"-b -c\",0,0);");
push(@tests, "basic_func(\"-g -P none\",\"-g -P none\",0,0);");
push(@tests, "basic_func(\"-g -P integrity\",\"-g -P integrity\",0,0);");
push(@tests, "basic_func(\"-g -P privacy\",\"-g -P privacy\",0,0);");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
   eval "&$_";
}
