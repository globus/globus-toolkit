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
use URI::Escape;
use POSIX;

use GlobusTransferAPIClient;

my $api = GlobusTransferAPIClient->new();

my $config_file = "security-options.conf";

sub setup_server($%)
{
    my %args = (
        Name => shift,
        FetchCredentialFromRelay => "True",
        CertificateFile => "",
        KeyFile => "",
        TrustedCertificateDirectory => "",
        IdentityMethod => "OAuth",
        OAuthServer => "\%(HOSTNAME)s",
        CILogonIdentityProvider => "",
        @_
    );
    my @cmd = ("globus-connect-multiuser-setup", "-c", $config_file);

    $ENV{ENDPOINT_NAME} = $args{Name};
    $ENV{FETCH_CREDENTIAL_FROM_RELAY} = $args{FetchCredentialFromRelay};
    $ENV{CERTIFICATE_FILE} = $args{CertificateFile};
    $ENV{KEY_FILE} = $args{KeyFile};
    $ENV{TRUSTED_CERTIFICATE_DIRECTORY} = $args{TrustedCertificateDirectory};
    $ENV{IDENTITY_METHOD} = $args{IdentityMethod};
    $ENV{CILOGON_IDENTITY_PROVIDER} = $args{CILogonIdentityProvider};
    $ENV{OAUTH_SERVER} = $args{OAuthServer};

    my ($pid, $in, $out, $err);
    $pid = open3($in, $out, $err, @cmd);
    close($in);
    waitpid($pid, 0);
    my $rc = $? >> 8;
    print STDERR join("", <$out>);
    print STDERR join("", <$err>);
    return $rc == 0;
}

sub myproxy_config_file()
{
    my $conffile;

    foreach $conffile ("/etc/sysconfig/myproxy-server",
                       "/etc/default/myproxy-server")
    {
        if (-r $conffile)
        {
            return $conffile;
        }
    }

    return undef;
}

sub myproxy_environment_vars(@)
{
    my $conffile = myproxy_config_file();
    my @vars = @_;
    my $fh;
    my $cmd;
    my $res = {};

    if (!$conffile)
    {
        return undef;
    }
    $cmd = "(. $conffile && printf \"\%s\\n\""
         . join("", map(" $_=\$$_", @vars))
         .")|";
    if (!open($fh, $cmd))
    {
        return undef;
    }
    while (<$fh>)
    {
        chomp;
        if (/([^=]*)=(.*)/)
        {
            $res->{$1} = $2;
        }
    }
    close($fh);
    return $res;
}


sub myproxy_credentials_match($$)
{
    my $certificate_file = shift;
    my $key_file = shift;
    my $res;

    $res = myproxy_environment_vars("X509_USER_CERT", "X509_USER_KEY") ||
        return undef;
    
    if (($res->{X509_USER_CERT} eq $certificate_file) &&
        ($res->{X509_USER_KEY} eq $key_file))
    {
        return 1;
    }
    return undef;
}

sub verify_myproxy_trusted_ca_dir($)
{
    my $trusted_ca_dir = shift;
    my $res;

    $res = myproxy_environment_vars("X509_CERT_DIR") || return undef;

    if ($res->{X509_CERT_DIR} eq $trusted_ca_dir)
    {
        return 1;
    }
    return undef;
}

sub gridftp_environment_vars()
{
    my @vars = @_;
    my $conffile;
    my $fh;
    my $res = {};

    foreach $conffile (</etc/gridftp.d/globus-connect-multiuser*>)
    {
        open($fh, "<$conffile") || next;

        while (<$fh>)
        {
            if (/^\s*\$([^=]*)\s+\"([^"]*)\"/)
            {
                $res->{$1} = $2;
            }
            elsif (/^\s*\$([^=]*)\s+(\S+)/)
            {
                $res->{$1} = $2;
            }
        }
        close($fh);
    }
    return $res;
}

sub gridftp_credentials_match($$)
{
    my ($certificate_file, $key_file) = @_;
    my $res;

    $res = gridftp_environment_vars();

    if (($res->{X509_USER_CERT} eq $certificate_file) &&
        ($res->{X509_USER_KEY} eq $key_file))
    {
        return 1;
    }
    return undef;
}

sub verify_gridftp_trusted_ca_dir($)
{
    my $trusted_ca_dir = shift;
    my $res;

    $res = gridftp_environment_vars();

    if ($res->{X509_CERT_DIR} eq $trusted_ca_dir)
    {
        return 1;
    }
    return undef;
}

sub endpoint_uses_myproxy_server($)
{
    my $endpoint = shift;
    my $json = $api->get_endpoint($endpoint);

    return defined($json->{myproxy_server});
}

sub endpoint_uses_cilogon($)
{
    my $endpoint = shift;
    my $json = $api->get_endpoint($endpoint);

    return $json->{oauth_server} eq 'cilogon.org';
}

sub cleanup($)
{
    my $endpoint_name = shift;
    my @cmd = ("globus-connect-multiuser-cleanup", "-c", $config_file, "-d");

    $ENV{ENDPOINT_NAME} = $endpoint_name;
    $ENV{ENDPOINT_PUBLIC} = "False";
    $ENV{ENDPOINT_DIR} = "/~/";

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

plan tests => 14;

# Prepare
my $random = int(1000000*rand());
my $endpoint_name = "SECURITY_OPTIONS_$random";
my $simple_ca_dir = mkdtemp("/tmp/XXXXXXXXX");
END { File::Path::rmtree($simple_ca_dir); }

my $host_credentials_dir = "$simple_ca_dir/host";
my $host_cert_request = "$host_credentials_dir/hostcert_request.pem";
my $host_cert = "$host_credentials_dir/hostcert.pem";
my $host_key = "$host_credentials_dir/hostkey.pem";

system("grid-ca-create -dir \"$simple_ca_dir\" -noint > /dev/null 2>&1");
open(my $tmpfh, ">$simple_ca_dir/passwd");
print $tmpfh "globus\n";
close($tmpfh);

my $simple_ca_hash = `openssl x509 -in $simple_ca_dir/cacert.pem -noout -hash`;
chomp($simple_ca_hash);

my $hostname = $ENV{PUBLIC_HOSTNAME};
if ($hostname !~ /\./)
{
    $hostname = $ENV{HOSTNAME};
}
if ($hostname !~ /\./)
{
    $hostname = (POSIX::uname())[1];
}

system("grid-cert-request -host \"$hostname\" -dir \"$host_credentials_dir\" -ca $simple_ca_hash > /dev/null 2>&1");

system("grid-ca-sign", "-dir", $simple_ca_dir,
        "-in", $host_cert_request,
        "-out", $host_cert);

# Create a server with FetchCredentialFromRelay = False, using the
# CertificateFile and KeyFile generated by the simple ca commands above
ok(setup_server($endpoint_name, FetchCredentialFromRelay => "False",
        CertificateFile => $host_cert, KeyFile => $host_key),
        "setup_server_with_existing_credential");

# Verify that MyProxy is using the certificate
ok(myproxy_credentials_match($host_cert, $host_key),
        "myproxy_credentials_match");

# Verify that GridFTP is using the certificate
ok(gridftp_credentials_match($host_cert, $host_key),
        "gridftp_credentials_match");
# Clean up servers
ok(cleanup($endpoint_name), "cleanup_first");
# Force cleanup
force_cleanup();

# Create a server with FetchCredentialFromRelay=False, using the
# CertificateFile and KeyFile generted from the simple ca commands above, and
# using a custom path to a trusted ca dir
my $trusted_ca_dir = mkdtemp("/tmp/XXXXXXX");
END {File::Path::rmtree($trusted_ca_dir);}

copy("$simple_ca_dir/cacert.pem", "$trusted_ca_dir/$simple_ca_hash.0");
ok(setup_server($endpoint_name, FetchCredentialFromRelay => "False",
        CertificateFile => $host_cert, KeyFile => $host_key,
        TrustedCertificateDirectory => $trusted_ca_dir),
        "setup_with_custom_cadir");

# Verify that MyProxy CA dir is $trusted_ca_dir
ok(verify_myproxy_trusted_ca_dir($trusted_ca_dir), 
        "myproxy_trusts_new_ca_dir");
# Verify that GridFTP CA dir is $trusted_ca_dir
ok(verify_gridftp_trusted_ca_dir($trusted_ca_dir), 
        "gridftp_trusts_new_ca_dir");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_second");
force_cleanup();

# Create a server using normal credentials, but using MyProxy authentication
# instead of OAuth
ok(setup_server($endpoint_name, IdentityMethod => "MyProxy",
    OAuthServer => ""),
        "setup_with_myproxy_as_idp");

# Verify that endpoint has myproxy in its json
ok(endpoint_uses_myproxy_server($endpoint_name),
    "endpoint_uses_myproxy_server");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_second");
force_cleanup();

# Create a server using normal credentials, but using CILogon with University
# of Chicago as IDP
ok(setup_server($endpoint_name, IdentityMethod => "CILogon", CILogonIdentityProvider => "University of Chicago", OAuthServer => ""), "setup_using_cilogon");

# Verify that GridFTP is configured with eppn callout and University of Chicago
# as IDP

# Verify that endpoint definition contains reference to CILogon OAuth server
ok(endpoint_uses_cilogon($endpoint_name),
    "endpoint_uses_cilogon");

# Clean up endpoint
ok(cleanup($endpoint_name), "cleanup_third");
force_cleanup();

# vim: filetype=perl:
