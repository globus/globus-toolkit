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
use POSIX "sys_wait_h";
use Test;

my @tests;
my @todo;

my $server_prog = './globus_io_tcp_test_server';
my $client_prog = './globus_io_tcp_test_client';

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
   my $saved_cert_dir;
   my $saved_user_cert;
   my $saved_user_key;
   my $saved_user_proxy;
   unlink('core');

   if(defined($ENV{X509_CERT_DIR}))
   {
       $saved_cert_dir = $ENV{X509_CERT_DIR};
   }
   if(defined($ENV{X509_USER_CERT}))
   {
       $saved_user_cert = $ENV{X509_USER_CERT};
   }
   if(defined($ENV{X509_USER_KEY}))
   {
       $saved_user_key = $ENV{X509_USER_KEY};
   }
   if(defined($ENV{X509_USER_PROXY}))
   {
       $saved_user_proxy = $ENV{X509_USER_PROXY};
   }

   if($sec_env == 0)
   {
#      use existing (good) gsi env
   }
   elsif($sec_env == 1)
   {
#      break gsi env
       $ENV{X509_CERT_DIR} = "";
   }
   elsif($sec_env == 2)
   {
#      break gsi env
       $ENV{X509_USER_CERT} = "";       
       $ENV{X509_USER_KEY} = "";       
   }
   
   my $command = "$server_prog $server_args |";
   #print "Running server: $command\n";
   $server_pid = open(SERVER, $command);

   if($server_pid == -1)
   {
       $errors .= "Unable to start server";
       goto end;
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
       goto end;
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

end:

   if(defined($saved_cert_dir)) 
   {
       $ENV{X509_CERT_DIR} = $saved_cert_dir;
   }
   elsif(defined($ENV{X509_CERT_DIR}))
   {
       delete $ENV{X509_CERT_DIR};
   }
   if(defined($saved_user_cert)) 
   {
       $ENV{X509_USER_CERT} = $saved_user_cert;
   }
   elsif(defined($ENV{X509_USER_CERT}))
   {
       delete $ENV{X509_USER_CERT};
   }
   if(defined($saved_user_key)) 
   {
       $ENV{X509_USER_KEY} = $saved_user_key;
   }
   elsif(defined($ENV{X509_USER_KEY}))
   {
       delete $ENV{X509_USER_KEY};
   }
   if(defined($saved_user_proxy)) 
   {
       $ENV{X509_USER_PROXY} = $saved_user_proxy;
   }
   elsif(defined($ENV{X509_USER_PROXY}))
   {
       delete $ENV{X509_USER_PROXY};
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
