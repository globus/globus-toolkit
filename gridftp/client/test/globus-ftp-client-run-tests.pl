#! /usr/bin/env perl

use strict;
use Test::Harness;
require 5.005;
use vars qw(@tests);

my $globus_location = $ENV{GLOBUS_LOCATION};

@tests = qw(
    globus-ftp-client-bad-buffer-test.pl
    globus-ftp-client-caching-get-test.pl
    globus-ftp-client-caching-transfer-test.pl
    globus-ftp-client-create-destroy-test.pl
    globus-ftp-client-exist-test.pl 
    globus-ftp-client-extended-get-test.pl
    globus-ftp-client-extended-put-test.pl
    globus-ftp-client-extended-transfer-test.pl
    globus-ftp-client-get-test.pl
    globus-ftp-client-lingering-get-test.pl
    globus-ftp-client-multiple-block-get-test.pl
    globus-ftp-client-partial-get-test.pl
    globus-ftp-client-partial-put-test.pl
    globus-ftp-client-partial-transfer-test.pl
    globus-ftp-client-plugin-test.pl
    globus-ftp-client-put-test.pl
    globus-ftp-client-size-test.pl 
    globus-ftp-client-transfer-test.pl
    globus-ftp-client-user-auth-test.pl
);
if(0 != system("grid-proxy-info -exists -hours 2") / 255)
{
    print "Security proxy required to run the tests.\n";
    exit 1;
}
chdir "$globus_location/test";

print "Running sanity check\n";
if(0 != system("./globus-ftp-client-get-test > /dev/null") / 255)
{
    print "Sanity check failed.\n";
    exit 1;
}
print "Server appears sane, running tests\n";

push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");
runtests(@tests);
