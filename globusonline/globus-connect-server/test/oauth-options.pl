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
use File::Compare;
use IPC::Open3;
use Test::More;
use POSIX;

use GlobusTransferAPIClient;

my $api = GlobusTransferAPIClient->new();

my $config_file = "oauth-options.conf";

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

sub setup_server($%)
{
    my %args = (
        EndpointName => shift,
        OAuthServer => "\%(HOSTNAME)s",
        OAuthServerBehindNat => "False",
        OAuthStylesheet => "",
        OAuthLogo => "",
        @_
    );
    my @cmd = ("globus-connect-server-setup", "-c", $config_file);

    $ENV{ENDPOINT_NAME} = $args{EndpointName};
    $ENV{OAUTH_SERVER} = $args{OAuthServer};
    $ENV{OAUTH_SERVER_BEHIND_NAT} = $args{OAuthServerBehindNat};
    $ENV{OAUTH_STYLESHEET} = $args{OAuthStylesheet};
    $ENV{OAUTH_LOGO} = $args{OAuthLogo};

    my $rc = diagsystem(@cmd);

    return $rc == 0;
}

sub endpoint_oauth_match($$)
{
    my ($endpoint_name, $oauth_server) = @_;
    my $json = $api->get_endpoint($endpoint_name);

    return ((exists($json->{oauth_server})) and
            ($json->{oauth_server} eq $oauth_server));
}

sub stylesheet_match($)
{
    my $css = shift;
    my $installed_css = "/usr/share/myproxy-oauth/myproxyoauth/static/site.css";

    if (!-r $installed_css)
    {
        return undef;
    }
    return compare($css, $installed_css) == 0;
}

sub logo_match($)
{
    my $logo = shift;
    my $installed_logo = "/usr/share/myproxy-oauth/myproxyoauth/static/oauth-options.png";

    if (!-r $installed_logo)
    {
        return undef;
    }
    return compare($logo, $installed_logo) == 0;
}

sub cleanup($)
{
    my $endpoint_name = shift;
    my @cmd = ("globus-connect-server-cleanup", "-c", $config_file, "-d");
    my $rc = diagsystem(@cmd);

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
    File::Path::rmtree("/var/lib/globus-connect-server");
    unlink("/var/lib/myproxy-oauth/myproxy-oauth.db");
}

plan tests => 12;

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
my $endpoint_name = "OAUTH_OPTIONS_$random";

# Try to create endpoint with different server name than hostname and
# server_behind_nat is false
ok(setup_server(
        $endpoint_name,
        OAuthServer => "oauth-$random.globus.org"),
        "create_with_different_hostname");

# Verify that endpoint has different server name
ok(endpoint_oauth_match($endpoint_name, "oauth-$random.globus.org"),
        "different_hostname_match");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_first");
force_cleanup();

# Create endpoint with different server name than hostname and
# server_behind_nat is true
ok(setup_server($endpoint_name,
        OAuthServer => "oauth-$random.globus.org",
        OAuthServerBehindNat => "True"),
        "create_with_different_hostname_behind_nat");

# Verify that endpoint has different server name
ok(endpoint_oauth_match($endpoint_name,
        "oauth-$random.globus.org"),
        "different_hostname_behind_nat_match");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_second");
force_cleanup();

# Create endpoint with specific stylesheet
ok(setup_server($endpoint_name,
        OAuthStylesheet => "oauth-options.css"),
        "create_with_stylesheet");

# Verify that oauth is configured with the stylesheet
ok(stylesheet_match("oauth-options.css"), "stylesheet_match");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_third");
force_cleanup();

# Create endpoint with specific logo
ok(setup_server($endpoint_name,
        OAuthLogo => "oauth-options.png"), "create_with_logo");

# Verify that oauth is configured with the logo
ok(logo_match("oauth-options.png"), "logo_match");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_fourth");
force_cleanup();

# vim: filetype=perl:
