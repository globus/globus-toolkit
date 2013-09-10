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

END {$?=0}

use strict;
use File::Path;
use IPC::Open3;
use Test::More;

use TempUser;

use GlobusTransferAPIClient;

$ENV{GLOBUSONLINE_USER} = 'gcmusharetest';

my $owner_api = GlobusTransferAPIClient->new(user=>'gcmusharetest');
my $friend_api = GlobusTransferAPIClient->new(user=>'gcmutest');

my $config_file = "sharing-test.conf";

sub cleanup
{
    my @cmd = ("globus-connect-multiuser-cleanup", "-c", $config_file, "-d",
            "-v");
    my ($pid, $in, $out, $err);
    $pid = open3($in, $out, $err, @cmd);
    close($in);
    waitpid($pid, 0);
    my $rc = $? >> 8;
    print STDERR join("", <$out>);
    print STDERR join("", <$err>);

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
    return $rc==0;
}

sub gcmu_setup($$)
{
    my $endpoint = shift;
    my $identity_method = shift;
    my @cmd = ("globus-connect-multiuser-setup", "-c", $config_file, "-v");
    
    $ENV{ENDPOINT_NAME} = $endpoint;
    $ENV{SECURITY_IDENTITY_METHOD} = $identity_method;

    # Create $endpoint
    my ($pid, $in, $out, $err);
    $pid = open3($in, $out, $err, @cmd);
    close($in);
    waitpid($pid, 0);
    my $rc = $? >> 8;
    print STDERR join("", <$out>);
    print STDERR join("", <$err>);

    return $rc == 0;
}

sub shared_endpoint_create($$;$$)
{
    my $shared_endpoint = shift;
    my $endpoint = shift;
    my $path = shift || "/~/";
    my $api = shift || $owner_api;
    my $res;

    $res = $api->shared_endpoint_create(
            $endpoint, $shared_endpoint, $path);

    return $res->{code} eq 'Created';
}

sub create_and_share_dir($$$$$$)
{
    my $name = shift;
    my $local_user = shift;
    my $go_user = shift;
    my $path = shift;
    my $perms = shift;
    my $api = shift;
    my $res;
    my ($uid, $gid, $home) = ((getpwnam($local_user))[2,3,7]);

    File::Path::mkpath( ["$home/$path"], 0, 0700 );
    chown $uid, $gid, "$home/$path";

    $res = $api->endpoint_access_add($name, path=>"/~/$path",
            principal=>$go_user, permissions=>$perms);

    return $res->{code} eq 'Created';
}


sub activate_endpoint($$$;$)
{
    my $endpoint = shift;
    my $username = shift;
    my $password = shift;
    my $api = shift || $owner_api;

    my $json = $api->activate($endpoint, $username, $password);

    return $json->{code} =~ '^Activated\.*' ||
        $json->{code} =~ '^AutoActivated\.*' ||
        $json->{code} =~ '^AlreadyActivated\.*';
}

sub transfer_file($$;%)
{
    my $endpoint = shift;
    my $user = shift;
    my %args = (
        api => $owner_api,
        source_dir => "",
        dest_dir => "",
        @_);
    my ($uid, $gid, $home) = ((getpwnam($user))[2,3,7]);
    my $fh;
    my $random_data = "";
    my $copied = "";
    my $res;
    my ($infile, $outfile);

    if ($args{source_dir} ne "")
    {
        $infile = "$args{source_dir}/$endpoint.in";
    }
    else
    {
        $infile = "$endpoint.in";
    }

    if ($args{dest_dir} ne "")
    {
        $outfile = "$args{dest_dir}/$endpoint.out";
    }
    else
    {
        $outfile = "$endpoint.out";
    }
    unlink($outfile);

    open($fh, ">$home/$infile");
    $random_data .= chr rand 255 for 1..100;
    $fh->print($random_data);
    $fh->close();
    chown $uid, $gid, "$home/$infile";

    $res = $args{api}->transfer($endpoint, $infile,
            $endpoint, $outfile);

    if ($res->{status} eq "FAILED")
    {
        return undef;
    }
    open($fh, "<$home/$outfile");
    read($fh, $copied, length($random_data));
    unlink("$home/$infile", "$home/$outfile");
    return $copied eq $random_data;
}

sub deactivate_endpoint($;$)
{
    my $endpoint = shift;
    my $api = shift || $owner_api;
    my $json = $api->deactivate($endpoint);

    return $json->{code} eq 'Deactivated' ||
            $json->{code} eq 'NotActivated';
}

# Prepare
my $random = int(1000000*rand());
my $endpoint = "SHARED-PHYSICAL-$random";
my $shared_endpoint = "gcmusharetest#SHARED-LOGICAL-$random";
my ($random_user, $random_pass) = TempUser::create_user();
my ($random_user2, $random_pass2) = TempUser::create_user();
if ((!$random_user) || (!$random_user2))
{
    exit(1);
}

plan tests => 19;

# Test Step #1:
# Create endpoint with MyProxy authentication
ok(gcmu_setup($endpoint, "MyProxy"), "create_endpoint_myproxy");

# Test Step #2:
# Activate endpoint using MyProxy
ok(activate_endpoint($endpoint, $random_user, $random_pass),
        "activate_with_myproxy");

# Test Step #3:
# Transfer file to myself
ok(transfer_file($endpoint, $random_user), "transfer_file_myproxy");

# Test Step #4:
# Create shared endpoint
ok(shared_endpoint_create($endpoint, $shared_endpoint),
        "shared_endpoint_create");

# Test Step #5:
# Create RW directory and share it
ok(create_and_share_dir($shared_endpoint, $random_user, "gcmutest",
        "RW", "rw", $owner_api), "shared_endpoint_access_add_rw");

# Test Step #6:
# Create RO directory and share it
ok(create_and_share_dir($shared_endpoint, $random_user, "gcmutest",
        "RO", "r", $owner_api), "shared_endpoint_access_add_r");

# Test Step #7:
# Activate shared endpoint
ok(activate_endpoint($shared_endpoint, $random_user, $random_pass),
        "activate_shared_owner");

# Test Step #8:
# Activate shared endpoint with 2nd user we share with
ok(activate_endpoint($shared_endpoint, $random_user2, $random_pass2,
        $friend_api), "activate_shared_friend");

# Test Step #9:
# Transfer file into rw using owner credentials
ok(transfer_file($endpoint, $random_user, api=>$owner_api,
        source_dir => "RW", dest_dir => "RW"),
        "transfer_via_shared_endpoint_owner");

# Test Step #10:
# Transfer file into rw using friend credentials
ok(transfer_file($shared_endpoint, $random_user, api=>$friend_api,
        source_dir => "RW", dest_dir => "RW"),
        "transfer_via_shared_endpoint_friend");

# Test Step #11:
# Try to transfer file into r dir using owner credentials
ok(!transfer_file($shared_endpoint, $random_user, api=>$owner_api,
        source_dir => "RO", dest_dir => "RO"),
        "transfer_via_shared_endpoint_owner_ro");

# Test Step #12:
# Try to transfer file from r to rw dir using owner credentials
ok(transfer_file($shared_endpoint, $random_user, api=>$owner_api,
        source_dir => "RO", dest_dir => "RW"),
        "transfer_via_shared_endpoint_owner_ro_to_rw");

# Test Step #13:
# Try to transfer file into r dir using friend credentials (should fail)
ok(!transfer_file($shared_endpoint, $random_user, api=>$friend_api,
        source_dir => "RO", dest_dir => "RO"),
        "transfer_via_shared_endpoint_friend_ro");

# Test Step #14:
# Try to transfer file from r to rw dir using friend credentials
ok(transfer_file($shared_endpoint, $random_user, api=>$friend_api,
        source_dir => "RO", dest_dir => "RW"),
        "transfer_via_shared_endpoint_friend_ro_to_rw");

# Test Step #15:
# Try to allow access to a path outside of the sharing restricted paths
ok(!create_and_share_dir($shared_endpoint, $random_user, "gcmutest",
        "NONE", "r", $owner_api),
        "shared_endpoint_access_add_restricted");

# Test Step #16:
# Deactivate friend's access to shared endpoint
ok(deactivate_endpoint($shared_endpoint, $friend_api),
        "deactivate_shared_endpoint_friend");

# Test Step #17:
# Deactivate access to shared endpoint
ok(deactivate_endpoint($shared_endpoint),
        "deactivate_shared_endpoint_owner");

# Test Step #18:
# Deactivate access to endpoint
ok(deactivate_endpoint($endpoint), "deactivate_endpoint_owner");

# Test Step #19:
# Clean up
ok(cleanup, "cleanup");

# vim: filetype=perl:
