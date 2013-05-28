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
use Test::More;
use POSIX;

require "transferapi.pl";

my $config_file = "gridftp-options.conf";

sub setup_server($%)
{
    my %args = (
        Name => shift,
        GridFTPHostname => "\%(HOSTNAME)s",
        GridFTPServerBehindNAT => "False",
        IncomingPortRange => "50000,51000",
        OutgoingPortRange => "",
        DataInterface => "\%(SHORT_HOSTNAME)s",
        RestrictPaths => "",
        Sharing => "False",
        SharingRestrictPaths => "",
        SharingStateDir => "",
        @_
    );
    my @cmd = ("globus-connect-multiuser-setup", "-c", $config_file);

    $ENV{ENDPOINT_NAME_VALUE} = $args{Name};
    $ENV{GRIDFTP_HOSTNAME_VALUE} = $args{GridFTPHostname};
    $ENV{SERVER_BEHIND_NAT_VALUE} = $args{GridFTPServerBehindNAT};
    $ENV{INCOMING_PORT_RANGE_VALUE} = $args{IncomingPortRange};
    $ENV{OUTGOING_PORT_RANGE_VALUE} = $args{OutgoingPortRange};
    $ENV{DATA_INTERFACE_VALUE} = $args{DataInterface};
    $ENV{RESTRICT_PATHS_VALUE} = $args{RestrictPaths};
    $ENV{SHARING_VALUE} = $args{Sharing};
    $ENV{SHARING_RESTRICT_PATHS_VALUE} = $args{SharingRestrictPaths};
    $ENV{SHARING_STATE_DIR_VALUE} = $args{SharingStateDir};

    return system(@cmd) == 0;
}

sub endpoint_server_match($$)
{
    my ($endpoint_name, $server_name) = @_;
    my $json = get_endpoint($endpoint_name);

    foreach my $gridftp_server (@{$json->{DATA}})
    {
        if ($gridftp_server->{hostname} eq $server_name)
        {
            return 1;
        }
    }
    return undef;
}

sub gridftp_setup_vars()
{
    my $conffile;
    my $fh;
    my $res = {};

    foreach $conffile (</etc/gridftp.d/globus-connect-multiuser*>)
    {
        open($fh, "<$conffile") || next;

        while (<$fh>)
        {
            s/#.*//;

            if (/^\s*(\S+)\s+\"([^"]*)\"/)
            {
                $res->{$1} = $2;
            }
            elsif (/^\s*(\S+)\s+(\S+)/)
            {
                $res->{$1} = $2;
            }
        }
        close($fh);
    }
    return $res;
}

sub gridftp_setup_match($$)
{
    my ($var, $val) = @_;
    my $setup = gridftp_setup_vars();

    return (exists($setup->{$var}) && $setup->{$var} eq $val);

}

sub endpoint_exists($)
{
    my $endpoint_name = shift;
    my $json = get_endpoint($endpoint_name);

    return $json->{DATA_TYPE} ne 'error';
}

sub cleanup($)
{
    my $endpoint_name = shift;
    my @cmd;
    my $rc;

    push(@cmd, "globus-connect-multiuser-cleanup", "-c", $config_file, "-d");
    return system(@cmd) == 0;
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

plan tests => 27;

# Prepare
my $random = int(1000000*rand());
my $endpoint_name = "GRIDFTP_OPTIONS_$random";
my $simple_ca_dir = mkdtemp("/tmp/XXXXXXXXX");
END { File::Path::rmtree($simple_ca_dir); }

my $hostname = $ENV{PUBLIC_HOSTNAME};
if ($hostname !~ /\./)
{
    $hostname = $ENV{HOSTNAME};
}
if ($hostname !~ /\./)
{
    $hostname = (POSIX::uname())[1];
}

# Try to create endpoint with different server name than hostname and
# server_behind_nat is false
ok(setup_server($endpoint_name,
        GridFTPHostname => "gridftp-$random.globus.org",
        GridFTPServerBehindNAT => "False"), "create_with_different_hostname");

# Verify that endpoint has different server name
ok(!endpoint_exists($endpoint_name),
        "didnt_create_endpoint");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_first");
force_cleanup();

# Create endpoint with different server name than hostname and
# server_behind_nat is true
ok(setup_server($endpoint_name,
        GridFTPHostname => "gridftp-$random.globus.org",
        GridFTPServerBehindNAT => "True"),
        "create_with_different_hostname_behind_nat");

# Verify that endpoint has different server name
ok(endpoint_server_match($endpoint_name, "gridftp-$random.globus.org"),
        "different_hostname_behind_nat_match");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_second");
force_cleanup();

# Create endpoint with incoming port range set to non-default value
my $incoming_port_range = "4000,4050";
ok(setup_server($endpoint_name,
        IncomingPortRange => $incoming_port_range),
    "create_with_incoming_port_range");

# Verify that gridftp is configured with incoming port range
ok(gridftp_setup_match("port_range", $incoming_port_range),
    "gridftp_incoming_port_match");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_third");
force_cleanup();

# Create endpoint with outgoing port range set to non-default value
my $outgoing_port_range = "5000,5050";
ok(setup_server($endpoint_name,
        OutgoingPortRange => $outgoing_port_range),
    "create_with_outgoing_port_range");

# Verify that gridftp is configured with outgoing port range
ok(gridftp_setup_match("\$GLOBUS_TCP_SOURCE_RANGE", $outgoing_port_range),
    "gridftp_outgoing_port_match");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_fourth");
force_cleanup();

# Create endpoint with data interface not matching hostname.
ok(setup_server($endpoint_name,
        DataInterface => "gridftp-$random.globus.org"),
    "create_with_data_interface");

# Verify that gridftp is configured with data interface
ok(gridftp_setup_match("data_interface", "gridftp-$random.globus.org"),
    "gridftp_data_interface_match");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_fifth");
force_cleanup();

# Create endpoint with restrict paths
ok(setup_server($endpoint_name,
        RestrictPaths => "R~"),
    "create_with_restrict_paths");

# Verify that gridftp is configured with restrict paths
ok(gridftp_setup_match("restrict_paths", "R~"), "gridftp_restrict_paths_match");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_sixth");
force_cleanup();


# Create endpoint with sharing
ok(setup_server($endpoint_name, Sharing => "True"), "create_with_sharing");

# Verify that gridftp is configured with sharing
ok(gridftp_setup_match("sharing_dn",
        "/C=US/O=Globus Consortium/OU=Globus Online/OU=Transfer User"
        ."/CN=__transfer__"), "gridftp_sharing_enabled");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_seventh");
force_cleanup();

# Create endpoint with sharing and sharing restrict paths
ok(setup_server($endpoint_name,
        Sharing => "True",
        SharingRestrictPaths => "R/tmp"),
    "create_with_sharing_restrict_paths");

# Verify that gridftp is configured with sharing and sharing restrict paths
ok(gridftp_setup_match("sharing_rp", "R/tmp"), 
    "gridftp_check_sharing_restrict_paths");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_eighth");
force_cleanup();

# Create endpoint with sharing and sharing state dir
ok(setup_server($endpoint_name,
        Sharing => "True",
        SharingStateDir => "/tmp/\$USER"),
    "create_with_sharing_state_dir");

# Verify that gridftp is configured with sharing and sharing state dir
ok(gridftp_setup_match("sharing_state_dir", "/tmp/\$USER"),
    "gridftp_check_sharing_state_dir");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_ninth");
force_cleanup();

# vim: filetype=perl:
