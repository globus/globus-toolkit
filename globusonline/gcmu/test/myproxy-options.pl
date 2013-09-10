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
use File::Temp;
use File::Copy;
use IPC::Open3;
use Test::More;
use POSIX;

use GlobusTransferAPIClient;

my $api = GlobusTransferAPIClient->new();

my $config_file = "myproxy-options.conf";

sub setup_server($%)
{
    my %args = (
        EndpointName => shift,
        MyProxyServer => "\%(HOSTNAME)s",
        MyProxyServerBehindNAT => "False",
        MyProxyCADir => "",
        MyProxyConfigFile => "",
        @_
    );
    my @cmd = ("globus-connect-multiuser-setup", "-c", $config_file);

    $ENV{ENDPOINT_NAME} = $args{EndpointName};
    $ENV{MYPROXY_SERVER} = $args{MyProxyServer};
    $ENV{MYPROXY_SERVER_BEHIND_NAT} = $args{MyProxyServerBehindNAT};
    $ENV{MYPROXY_CA_DIR} = $args{MyProxyCADir};
    $ENV{MYPROXY_CONFIG_FILE} = $args{MyProxyConfigFile};

    my ($pid, $in, $out, $err);
    $pid = open3($in, $out, $err, @cmd);
    close($in);
    waitpid($pid, 0);
    my $rc = $? >> 8;
    print STDERR join("", <$out>);
    print STDERR join("", <$err>);

    return $rc == 0;
}

sub endpoint_myproxy_match($$)
{
    my ($endpoint_name, $myproxy_server) = @_;
    my $json = $api->get_endpoint($endpoint_name);

    return ((exists($json->{myproxy_server})) and
            ($json->{myproxy_server} eq $myproxy_server));
}

sub myproxy_setup_match($$)
{
    my ($var, $val) = @_;
    my $config_file = "/var/lib/globus-connect-multiuser/myproxy-server.conf";
    my $fh;

    open ($fh, "<$config_file") || return undef;
    while (<$fh>)
    {
        chomp;
        s/#.*//;
        if (/(\S+)\s+"([^"]+)"/)
        {
            if ($1 eq $var)
            {
                return ($2 eq $val);
            }
        }
        elsif (/(\S+)\s+(\S+)/)
        {
            if ($1 eq $var)
            {
                return ($2 eq $val);
            }
        }
    }
    return undef;
}

sub myproxy_env_file()
{
    foreach my $file ("/etc/sysconfig/myproxy-server",
                      "/etc/default/myproxy-server")
    {
        if (-r $file)
        {
            return $file;
        }
    }
    return undef;
}

sub myproxy_config_file_path_match($)
{
    my $path = shift;
    my $env_file;
    my $fh;
    if (! -r $path)
    {
        return undef;
    }
    $env_file = myproxy_env_file();
    if (!$env_file)
    {
        return undef;
    }

    open($fh, ". $env_file; echo \$MYPROXY_OPTIONS|") || return undef;

    while (<$fh>)
    {
        if (/-c\s+$path/)
        {
            return 1;
        }
    }
    close($fh);
    return undef;
}

sub cleanup($)
{
    my $endpoint_name = shift;
    my @cmd = ("globus-connect-multiuser-cleanup", "-c", $config_file, "-d");

    my ($pid, $in, $out, $err);
    $pid = open3($in, $out, $err, @cmd);
    close($in);
    waitpid($pid, 0);
    my $rc = $? >> 8;
    print STDERR join("", <$out>);
    print STDERR join("", <$err>);
    return $rc == 0;
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
}

plan tests => 10;

# Prepare
my $hostname = $ENV{PUBLIC_HOSTNAME};
if ($hostname !~ /\./)
{
    $hostname = $ENV{HOSTNAME};
}
if ($hostname !~ /\./)
{
    $hostname = (POSIX::uname())[1];
}
my $random = int(1000000*rand());
my $endpoint_name = "MYPROXY_OPTIONS_$random";

# Try to create endpoint with different server name than hostname and
# server_behind_nat is false
ok(!setup_server(
        $endpoint_name,
        MyProxyServer => "myproxy-$random.globus.org"),
        "create_with_different_hostname");

# Create endpoint with different server name than hostname and
# server_behind_nat is true
ok(setup_server($endpoint_name,
        MyProxyServer => "myproxy-$random.globus.org",
        MyProxyServerBehindNAT => "True"),
        "create_with_different_hostname_behind_nat");

# Verify that endpoint has different server name
ok(endpoint_myproxy_match($endpoint_name,
        "myproxy-$random.globus.org"),
        "different_hostname_behind_nat_match");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_second");
force_cleanup();

# Create endpoint with specific myproxy ca dir
my $ca_dir_root = mkdtemp("/tmp/XXXXXXX");
END { File::Path::rmtree($ca_dir_root); }
my $ca_dir = "$ca_dir_root/ca";
ok(setup_server($endpoint_name,
        MyProxyCADir => $ca_dir),
        "create_with_myproxy_ca_dir");

# Verify that myproxy is configured with incoming port range
ok(myproxy_setup_match("certificate_issuer_cert", "$ca_dir/cacert.pem"),
    "myproxy_ca_dir_match");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_third");
force_cleanup();

# Create endpoint with specific myproxy_config
my $myproxy_config = "$ca_dir_root/myproxy-config-file";
ok(setup_server($endpoint_name,
        MyProxyConfigFile => $myproxy_config),
    "create_with_myproxy_config");

# Verify that gridftp is configured with outgoing port range
ok(myproxy_config_file_path_match($myproxy_config),
    "myproxy_config_file_path_match");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_fourth");
force_cleanup();

# vim: filetype=perl:
