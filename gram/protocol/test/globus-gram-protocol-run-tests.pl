#! /usr/bin/env perl

use strict;
use Test::Harness;
require 5.005;
use vars qw(@tests);
$|=1;

my $globus_location = $ENV{GLOBUS_LOCATION};
my $contact;

@tests = qw(
    globus-gram-protocol-allow-attach-test.pl
    globus-gram-protocol-error-test.pl
    globus-gram-protocol-io-test.pl
    globus-gram-protocol-pack-test.pl
);
if(0 != system("grid-proxy-info -exists -hours 2") / 255)
{
    print STDERR "Security proxy required to run the tests.\n";
    exit 1;
}
chdir "$globus_location/test";

runtests(@tests);
