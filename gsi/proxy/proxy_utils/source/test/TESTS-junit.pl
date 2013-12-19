#! /usr/bin/perl

require 5.005;

use warnings;
use strict;
use Cwd;

my $harness;
BEGIN {
    my $xmlfile = 'globus-proxy-utils-test.xml';

    eval "use TAP::Harness::JUnit";
    if ($@)
    {
        eval "use TAP::Harness;";

        if ($@)
        {
            die "Unable to find JUnit TAP formatter";
        }
        else
        {
            $harness = TAP::Harness->new( {
                formatter_class => 'TAP::Formatter::JUnit',
                merge => 1
            } );
        }
        open(STDOUT, ">$xmlfile");
    }
    else
    {
        $harness = TAP::Harness::JUnit->new({
                                xmlfile => $xmlfile,
                                merge => 1});
    }
}
my $cwd = getcwd();
$ENV{X509_CERT_DIR} = $cwd;
$ENV{X509_USER_CERT} = "$cwd/usercert.pem";
$ENV{X509_USER_KEY} = "$cwd/userkey.pem";

chmod 0600, $ENV{X509_USER_KEY};
chmod 0644, $ENV{X509_USER_CERT};
chmod 0755, $cwd;

my @tests = qw(grid-proxy-utils-test.pl proxy-order-test.pl);

$harness->runtests(@tests);
