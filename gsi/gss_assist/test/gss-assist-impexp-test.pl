#!/usr/bin/env perl

use strict;
use POSIX;
use POSIX "sys_wait_h";
use Test;
use Cwd;

my @tests;
my @todo;

my $server_prog = './gss-assist-impexp-accept';
my $client_prog = './gss-assist-impexp-init';

$ENV{X509_CERT_DIR} = cwd();
$ENV{X509_USER_PROXY} = "testcred.pem";

sub basic_func
{
    my ($errors,$rc) = ("",0);
    my $expect_failure = shift;
    my $sec_env = shift;
    my $result;
    my $server_pid;
    my $client_pid;
    my $port;
    
   unlink('core');

   if($sec_env == 0)
   {
       $ENV{X509_CERT_DIR} = cwd();
       $ENV{X509_USER_PROXY} = "testcred.pem";
   }
   elsif($sec_env == 1)
   {
       $ENV{X509_CERT_DIR} = "";
       $ENV{X509_USER_PROXY} = "testcred.pem";       
   }
   elsif($sec_env == 2)
   {
       $ENV{X509_CERT_DIR} = cwd();
       $ENV{X509_USER_PROXY} = "";       
   }

   $server_pid = open(SERVER, "$server_prog |");

   if($server_pid == -1)
   {
       $errors .= "Unable to start server";
       return;
   }

   $port = <SERVER>;
   chomp($port);
   $port =~ s/Socket has port \#//;

   $client_pid = open(CLIENT, "$client_prog localhost $port|");

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

   if($errors eq "" || $expect_failure)
   {
       ok('success', 'success');
   }
   else
   {
       ok($errors, 'success');
   }
}

push(@tests, "basic_func(0,0);");
push(@tests, "basic_func(1,1);");
push(@tests, "basic_func(1,2);");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
   eval "&$_";
}
