#! /usr/bin/env perl

use strict;
use Test::Harness;
use FtpTestLib;
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
if(0 != system("grid-proxy-info -exists -hours 2") / 256)
{
    print "Security proxy required to run the tests.\n";
    exit 1;
}

print "Running sanity check\n";
my ($source_host, $source_file, $local_copy1) = setup_remote_source();
my ($local_copy2) = setup_local_source();
my ($dest_host, $dest_file) = setup_remote_dest();

if(0 != system("./globus-ftp-client-get-test -s gsiftp://$source_host$source_file > /dev/null 2>&1") / 256)
{
    print "Sanity check of source (gsiftp://$source_host$source_file) failed.\n";
    exit 1;
}
if(0 != system("./globus-ftp-client-put-test -d gsiftp://$dest_host$dest_file < $local_copy2 > /dev/null 2>&1") / 256)
{
    print "Sanity check of local source ($local_copy2) to dest (gsiftp://$dest_host$dest_file) failed.\n";
    clean_remote_file($dest_host, $dest_file);
    exit 1;
}
clean_remote_file($dest_host, $dest_file);
print "Server appears sane, running tests\n";

push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");
runtests(@tests);
