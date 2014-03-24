#! /usr/bin/perl

use strict;
use Test::More;
use File::Temp;

my $valgrind="";

if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-proxy-utils-test-\%p.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

print "# PATH = $ENV{PATH}\n";
print "# X509_CERT_DIR = $ENV{X509_CERT_DIR}\n";

sub test_proxy
{
    my $case = shift;
    my $proxy_format = $case->[0];
    my $proxy_type = $case->[1];
    my $expect = $case->[2];
    my $testname = $case->[3];
    my $result = '';
    my $proxy_created = 1;
    my $type_determined = 1;
    my $proxy_file = mktemp( "proxy-XXXXXXXX" );

    $ENV{X509_USER_PROXY}=$proxy_file;

    ok(system("$valgrind grid-proxy-init $proxy_format $proxy_type > /dev/null") == 0, "create_proxy $proxy_format $proxy_type");

    $result = `$valgrind grid-proxy-info -type`;
    ok($? == 0, "grid-proxy-info $proxy_format $proxy_type");
    $result =~ s/\s*$//;

    ok($result eq $expect, "grid-proxy-info type is $expect");

    unlink($proxy_file);
}

my @tests = (
    [ "", "", "RFC 3820 compliant impersonation proxy", "default_proxy_type" ],
    [ "-draft", "", "Proxy draft (pre-RFC) compliant impersonation proxy" ,
        "draft_proxy_type"],
    [ "-rfc", "", "RFC 3820 compliant impersonation proxy",
        "rfc_proxy_type"],
    [ "-old", "", "full legacy globus proxy",
        "legacy_proxy_type"],

    [ "", "-limited", "RFC 3820 compliant limited proxy",
        "default_limited_proxy_type"],
    [ "-draft", "-limited", "Proxy draft (pre-RFC) compliant limited proxy",
        "draft_limited_proxy_type"],
    [ "-rfc", "-limited", "RFC 3820 compliant limited proxy",
        "rfc_limited_proxy_type"],
    [ "-old", "-limited", "limited legacy globus proxy",
        "old_limited_proxy_type"],

    [ "", "-independent", "RFC 3820 compliant independent proxy",
        "independent_proxy_type"],
    [ "-draft", "-independent", "Proxy draft (pre-RFC) compliant independent proxy",
        "draft_independent_proxy_type"],
    [ "-rfc", "-independent", "RFC 3820 compliant independent proxy",
        "rfc_independent_proxy_type"]
);

plan tests => 3*scalar(@tests);

foreach (@tests)
{
    eval test_proxy($_);
}
