#!/usr/bin/env perl

use strict;
use POSIX;
use POSIX "sys_wait_h";
use Test::More;

my @tests;
my @todo;

my $server_prog = './gss-assist-impexp-accept';
my $client_prog = './gss-assist-impexp-init';

my ($valgrind_client, $valgrind_server) = ('', '');
if (exists $ENV{VALGRIND})
{
    $valgrind_client = "valgrind --log-file=VALGRIND-gss_assist_impexp_init.log";
    $valgrind_server = "valgrind --log-file=VALGRIND-gss_assist_impexp_accept.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind_client .= ' ' . $ENV{VALGRIND_OPTIONS};
        $valgrind_server .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

sub basic_func
{
    my ($errors,$rc) = ("",0);
    my $expect_failure = shift;
    my $sec_env = shift;
    my $test_name = shift;
    my $result;
    my $server_pid;
    my $client_pid;
    my $port;

   if($sec_env == 1)
   {
       $ENV{X509_CERT_DIR} = "/bogus";
   }
   elsif($sec_env == 2)
   {
       $ENV{X509_USER_PROXY} = "/bogus";
   }

   $server_pid = open(SERVER, "$valgrind_server $server_prog |");

   if($server_pid == -1)
   {
       $errors .= "Unable to start server";
       return;
   }

   $port = <SERVER>;
   chomp($port);
   $port =~ s/Socket has port \#//;

   $client_pid = open(CLIENT, "$valgrind_client $client_prog localhost $port|");

   if($client_pid == -1)
   {
       $errors .= "Unable to start client";
       return;
   }
   
   waitpid($server_pid,0);
   my $server_exit_code = $? >> 8;

   if ($server_exit_code != 0 && $server_exit_code != 77)
   {
       $errors .= "Server exited abnormally. \n The following output was generated:\n";
       while(<SERVER>)
       {
           $errors .= $_;
       }
   }

   waitpid($client_pid,0);
   my $client_exit_code = $? >> 8;

   if ($client_exit_code != 0 && $client_exit_code != 77)
   {
       $errors .= "Client exited abnormally. \n The following output was generated:\n";
       while(<CLIENT>)
       {
           $errors .= $_;
       }
   }
   
   close(CLIENT);
   close(SERVER);

   SKIP: {
       skip "Non-transportable context", 1 unless($client_exit_code != 77 && $server_exit_code != 77);
       ok($errors eq "" || $expect_failure, $test_name)
   }
}

push(@tests, "basic_func(0,0, \"default-sec-env\");");
push(@tests, "basic_func(1,1, \"unset-x509-cert-dir\");");
push(@tests, "basic_func(1,2, \"unsetx509-user-proxy\");");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
   eval "&$_";
}
