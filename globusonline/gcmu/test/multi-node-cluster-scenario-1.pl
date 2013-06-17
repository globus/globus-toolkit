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

# Scenario #1:
# Multiple File Servers and a Shared Identity Provider in a Cluster

BEGIN
{
    $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = "0";
}

END {$?=0}

use strict;
use File::Path 'rmtree';
use File::Compare 'compare';
use IPC::Open3;
use POSIX;
use LWP;
use URI::Escape;
use Test::More;

use TempUser;

require "barrier.pl";
require "transferapi.pl";

my $config_file = "multi-node-cluster-scenario.conf";

sub diagsystem(@)
{
    my @cmd = @_;
    my ($pid, $in, $out, $err);
    my ($outdata, $errdata);
    $pid = open3($in, $out, $err, @cmd);
    close($in);
    local($/);
    $outdata = <$out>;
    $errdata = <$err>;
    diag("$cmd[0] stdout: $outdata") if ($outdata);
    diag("$cmd[0] stderr: $errdata") if ($errdata);
    waitpid($pid, 0);
    return $?;
}

sub cleanup()
{
    my @cmd;
    my $rc;

    $cmd[0] = "globus-connect-multiuser-cleanup";
    $cmd[1] = "-c";
    $cmd[2] = $config_file;
    $cmd[3] = "-d";
    $rc = diagsystem(@cmd);

    # Just to make sure that doesn't fail
    foreach my $f (</etc/gridftp.d/globus-connect*>)
    {
        unlink($f);
    }
    foreach my $f (</etc/myproxy.d/globus-connect*>)
    {
        unlink($f);
    }
    rmtree("/var/lib/globus-connect-multiuser");
    unlink("/var/lib/myproxy-oauth/myproxy-oauth.db");
    return $rc == 0;
}

sub gcmu_setup($)
{
    my $endpoint = shift;
    my @cmd;
    my $rc;
    
    $ENV{ENDPOINT_NAME} = $endpoint;

    # Create $endpoint
    @cmd = ("globus-connect-multiuser-setup", "-c", $config_file, "-v");

    return diagsystem(@cmd)==0;
}

sub activate_endpoint($$$)
{
    my ($endpoint, $user, $pass) = @_;
    my $json;

    $json = activate($endpoint, $user, $pass);

    return $json->{code} =~ '^Activated\.*' ||
        $json->{code} =~ '^AutoActivated\.*' ||
        $json->{code} =~ '^AlreadyActivated\.*';
}

sub autoactivate_endpoint($)
{
    my ($endpoint) = @_;
    my $json;

    $json = autoactivate($endpoint);

    return $json->{code} =~ '^Activated\.*' ||
        $json->{code} =~ '^AutoActivated\.*' ||
        $json->{code} =~ '^AlreadyActivated\.*';
}

sub deactivate_endpoint($)
{
    my $endpoint = shift;
    my $json;

    $json = deactivate($endpoint);

    return $json->{code} =~ '^Deactivated';
}

sub transfer_between_endpoints($$$$)
{
    my $json = transfer(@_);
    return $json->{status} eq 'SUCCEEDED';
}

# Prepare
my $test_mode;
my $hostname;

if ($ENV{PUBLIC_HOSTNAME}) {
    $hostname = $ENV{PUBLIC_HOSTNAME};
} else {
    $hostname = (POSIX::uname())[1];
}
plan tests => 20;

set_barrier_prefix("multi-node-cluster-scenario-1-");
set_barrier_print(\&diag);

my $res = barrier(1, hostname=>$hostname);
die "Barrier error" if $res eq 'ERROR';

# Determine our rank in the list of machines from the first barrier
my $rank = rank(@{$res});
my $size = scalar(@{$res});

$ENV{ID_NODE} = $res->[0]->{hostname};
$ENV{WEB_NODE} = $res->[0]->{hostname};
$ENV{IO_NODE} = $hostname;

my ($test_user, $test_pass);
if ($rank == 0)
{
    ($test_user, $test_pass) = TempUser::create_user();
}

foreach my $method ("OAuth", "MyProxy")
{
    # To match failures with test step numbers, add 9 for MyProxy pass through
    # the tests
    my $random = int(1000000*rand());
    my $short_hostname;
    my $endpoint;

    ($short_hostname = $hostname) =~ s/\..*//;
    $endpoint = "MULTI-$short_hostname-$random";

    $ENV{SECURITY_IDENTITY_METHOD} = $method;
    set_barrier_prefix("multi-node-cluster-scenario-1-$method-");

    # Test step #1-2:
    # Create ID, I/O and Web server on node 0
    # Activate endpoint living on ID node
    SKIP: {
        skip "Web/ID node operations only", 2 unless ($rank == 0);

        ok(gcmu_setup($endpoint), "setup_id_web_io_$method");
        ok(activate_endpoint($endpoint, $test_user, $test_pass),
            "activate_endpoint_$method");
    }

    # barrier to wait for id/web node to configure
    if ($rank == 0)
    {
        $res = barrier(2, rank=>$rank, user=>$test_user);
        die "Barrier error" if $res eq 'ERROR';
    }
    else
    {
        $res = barrier(2, rank=>$rank);
        die "Barrier error" if $res eq 'ERROR';
        if (!$test_pass)
        {
            $test_user = (map { $_->{user} } grep {$_->{rank} == 0} @{$res})[0];
            ($test_user, $test_pass) = TempUser::create_user($test_user);
        }
    }

    # Test step #3-4:
    # Create I/O servers on other nodes
    # Autoactivate other nodes (should work because they use the same ID/Web
    # server)
    SKIP: {
        skip "I/O node only", 2 unless ($rank > 0);

        ok(gcmu_setup($endpoint), "setup_io_$method");
        ok(autoactivate_endpoint($endpoint), "autoactivate_io_$method");
    }

    # barrier to wait for I/O nodes to configure and activate
    $res = barrier(3, rank=>$rank, endpoint=>$endpoint);
    die "Barrier error" if $res eq 'ERROR';

    my $source_endpoint = $endpoint;
    my $dest_endpoint = $res->[($rank+1) % $size]->{endpoint};

    # Test Step #5-7:
    # Transfer file between local and remote endpoints and vice versa, compare
    SKIP: {
        skip "Not enough nodes for transfer", 3 unless $size >= 2;
        my $fh;
        my ($uid, $gid, $homedir) = ((getpwnam($test_user))[2,3,7]);
        my ($infile, $outfile, $fh);
        my $random_data = '';

        $infile = "$source_endpoint.in";
        $outfile = "$source_endpoint.out";

        open($fh, ">$homedir/$infile");
        $random_data .= chr rand 255 for 1..100;
        print $fh $random_data;
        $fh->close();

        chown $uid, $gid, $infile;
        diag("Transferring $infile from $source_endpoint to $dest_endpoint");
        ok(transfer_between_endpoints($source_endpoint, $infile,
                $dest_endpoint, $infile),
                "transfer_between_endpoints_$method");
        diag("Transferring $infile from $dest_endpoint to $source_endpoint");
        ok(transfer_between_endpoints($dest_endpoint, $infile,
                $source_endpoint, $outfile),
                "transfer_between_endpoints_$method");
        diag("Comparing $homedir/$infile and $homedir/$outfile");
        ok(compare("$homedir/$infile", "$homedir/$outfile") == 0,
                "compare_$method");

        unlink("$homedir/$infile", "$homedir/$outfile");
    }

    # barrier to wait for transfer tests to complete before cleaning up
    $res = barrier(4, rank=>$rank);
    die "Barrier error" if $res eq 'ERROR';

    # Test Step #8:
    # Deactivate endpoints
    ok(deactivate_endpoint($endpoint), "deactivate_endpoint_$method");

    $res = barrier(5, rank=>$rank);
    die "Barrier error" if $res eq 'ERROR';

    SKIP: {
        skip "I/O node only", 1 if $rank == 0;
        # Test Step #9:
        # Clean up gcmu
        ok(cleanup(), "cleanup_$method");
    }

    $res = barrier(6, rank=>$rank);
    die "Barrier error" if $res eq 'ERROR';

    SKIP: {
        skip "Web/ID node only", 1 if $rank != 0;
        # Test Step #10:
        # Clean up gcmu
        ok(cleanup(), "cleanup_$method");
    }
}

# vim: filetype=perl :
