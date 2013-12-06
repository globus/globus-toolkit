#! /usr/bin/perl

require 5.005;
use warnings;
use strict;
use File::Basename;
use Test::Harness;
use Cwd;
use lib(dirname($0));
use vars qw(@tests);

my $test_result=1;

$|=1;

my $contact;

@tests = qw(
    globus-gram-protocol-allow-attach-test.pl
    globus-gram-protocol-error-test.pl
    globus-gram-protocol-io-test.pl
    globus-gram-protocol-pack-test.pl
    pack-with-extensions-test.pl
    create-extensions-test.pl
    unpack-message-test.pl
    unpack-with-extensions-test.pl
    unpack-job-request-reply-with-extensions-test.pl
    unpack-status-reply-with-extensions-test.pl
);

$test_result = eval { runtests(@tests); };

if(!defined($test_result))
{
    print $@;
    $test_result=1;
}
else
{
    $test_result=0;
}

exit($test_result);
