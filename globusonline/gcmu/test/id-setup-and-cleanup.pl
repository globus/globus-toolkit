#! /usr/bin/perl
#
# Copyright 1999-2013 University of Chicago
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

BEGIN
{
    $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = "0";
}

END {$?=0}

use strict;
use File::Path;
use File::Temp;
use Test::More;

plan tests => 5;

# Prepare
my $config_file = "test-id.conf";

# Test Step #1:
# Setup ID server
ok(setup_id_server() == 0, "setup_id_server");

# Test Step #2:
# Check that myproxy-server process is running
ok(is_myproxy_server_running() == 1, "is_myproxy_server_running");

# Test Step #3:
# Fetch trust roots from myproxy server and verify that the GCMU CA cert is
# present
ok(fetch_and_compare_trust_roots() == 0, "fetch_and_compare_trust_roots");

# Test Step #4:
# Clean up the ID server
ok(cleanup() == 0, "cleanup");

# Test Step #5:
# Check that myproxy-server is not running
ok(is_myproxy_server_running() == 0, "is_myproxy_server_not_running");

# Remove everything in GCMU dir
force_cleanup();

sub setup_id_server()
{
    my @cmd = ("globus-connect-multiuser-id-setup", "-c", $config_file);

    return system(@cmd);
}

sub is_myproxy_server_running()
{
    my @cmd = ("/etc/init.d/myproxy-server", "status");
    return system(@cmd) == 0;
}

sub fetch_and_compare_trust_roots()
{
    my @cmd;
    my $fh;
    my $rc;
    my $ca_hash;
    $ENV{X509_USER_CERT} = "";
    $ENV{X509_USER_KEY} = "";
    $ENV{X509_USER_PROXY} = "";
    $ENV{X509_CERT_DIR} = mkdtemp("/tmp/test-id-XXXXXXX");

    if (! open($fh, "myproxy-get-trustroots -b -s localhost 2>&1 |"))
    {
        $rc |= 1;
    }
    else
    {
        while(<$fh>)
        {
            if (/MYPROXY_SERVER_DN="([^"]*)"/)
            {
                $ENV{MYPROXY_SERVER_DN} = $1;
                last;
            }
        }
    }
    $rc |= system("myproxy-get-trustroots -b -s localhost");

    @cmd = ("openssl", "x509", "-hash", "-in",
        "/var/lib/globus-connect-multiuser/myproxy-ca/cacert.pem");
    if (! open($fh, "-|", @cmd))
    {
        $rc |= 2;
    }
    else
    {
        chomp($ca_hash = <$fh>);

        if (! -f $ENV{X509_CERT_DIR}."/$ca_hash.0")
        {
            $rc |= 3;
        }
    }

    File::Path::rmtree($ENV{X509_CERT_DIR});

    return $rc;
}

sub cleanup()
{
    my @cmd;
    my $rc;

    $cmd[0] = "globus-connect-multiuser-id-cleanup";
    $cmd[1] = "-c";
    $cmd[1] = $config_file;
    $rc = system(@cmd);
}

sub force_cleanup()
{
    # Just to make sure that doesn't fail
    foreach my $f (</etc/gridftp.d/globus-connect*>)
    {
        unlink($f);
    }
    foreach my $f (</etc/myproxy.d/globus-connect*>)
    {
        unlink($f);
    }
    File::Path::rmtree("/var/lib/globus-connect-multiuser");
    unlink("/var/lib/myproxy-oauth/myproxy-oauth.db");
    return 0;
}
