#! /usr/bin/perl

# This tests permutations in the proxy file format order, as well as support
# for PKCS8-encoded private keys in proxies
use strict;
use Test::More;
use IO::Handle;

use File::Temp;
use Globus::Core::Paths;

my $valgrind="";

if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-proxy-order-test-\%p.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}
my $old_umask = umask(077);
my ($proxy_fh, $proxy_file) = mkstemp( "/tmp/proxytest.XXXXXXXX" );
$proxy_fh->autoflush(1);
umask($old_umask);

$ENV{X509_USER_PROXY} = $proxy_file;
system("$valgrind $Globus::Core::Paths::bindir/grid-proxy-init > /dev/null");
open($proxy_fh, "+<$proxy_file");

my $data = '';
my %elements = {};

while (<$proxy_fh>)
{
    if (/-----BEGIN CERTIFICATE-----/)
    {
        $data = $_;
    }
    elsif (/-----END CERTIFICATE-----/)
    {
        $data .= $_;
        if (!exists($elements{proxy_cert}))
        {
            $elements{proxy_cert} = $data;
        }
        else
        {
            if (!exists($elements{id_cert}))
            {
                $elements{id_cert} = '';
            }

            $elements{id_cert} .= $data;
        }
        $data = '';
    }
    elsif (/-----BEGIN RSA PRIVATE KEY-----/)
    {
        $data = $_;
    }
    elsif (/-----END RSA PRIVATE KEY-----/)
    {
        $data .= $_;
        $elements{proxy_key} = $data;
        $data = '';

        $elements{'proxy_key.pkcs8'} = `openssl pkcs8 -in "$proxy_file" -outform PEM -topk8 -nocrypt`;
    }
    else
    {
        $data .= $_;
    }
}

sub test_proxy_order
{
    my $order = shift;

    truncate $proxy_fh, 0;
    seek($proxy_fh, 0, 0);
    for my $element (split(/:/, $order))
    {
        print $proxy_fh $elements{$element};
    }

    ok(system("$valgrind $Globus::Core::Paths::$bindir/grid-proxy-info > /dev/null 2>&1") == 0, "proxy order $order");
}

my @permutations = qw(
                proxy_cert:proxy_key:id_cert 
                 proxy_cert:id_cert:proxy_key
                 proxy_key:proxy_cert:id_cert
                 proxy_key:id_cert:proxy_cert
                 id_cert:proxy_cert:proxy_key
                 id_cert:proxy_key:proxy_cert);
my @tests = @permutations;
push(@tests, map { $_ =~ s/proxy_key/proxy_key.pkcs8/; $_ } @permutations);

plan tests => scalar(@tests);

foreach (@tests)
{
    eval test_proxy_order($_);
}

END {
    unlink($proxy_file);
}
