#! perl

use strict;
use Test::Harness;
require 5.005;
use vars qw(@tests);

my $globus_location = $ENV{GLOBUS_LOCATION};

$ENV{X509_USER_PROXY} = testcred.pem;
$ENV{X509_CERT_DIR} = `pwd`;

@tests = qw(gssapi-anonymous-test.pl
            gssapi-delegation-test.pl
            gssapi-limited-delegation-test.pl
            gssapi-delegation-compat-test.pl
            gssapi-group-test.pl
           );

if(0 != system("$globus_location/bin/grid-proxy-info -exists -hours 2") / 255)
{
    print "Security proxy required to run the tests.\n";
    exit 1;
}

push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");

runtests(@tests);
