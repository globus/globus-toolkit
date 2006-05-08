#! /usr/bin/env perl

#
# Portions of this file Copyright 1999-2005 University of Chicago
# Portions of this file Copyright 1999-2005 The University of Southern California.
#
# This file or a portion of this file is licensed under the
# terms of the Globus Toolkit Public License, found at
# http://www.globus.org/toolkit/download/license.html.
# If you redistribute this file, with or without
# modifications, you must include this notice in the file.
#

#
# Try reading an url by passing in a bad data buffer

use strict;
use POSIX;
use Test;
use FtpTestLib;

my $test_exec = './globus-ftp-client-bad-buffer-test';

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my @tests;
my @todo;

my ($proto) = setup_proto();
my ($source_host, $source_file, $local_copy) = setup_remote_source();

# Test 1: Bad buffer test
# Success if the transfer fails with exit code 2
sub bad_buffer
{
    my ($errors,$rc) = ("",0);
    my ($output);

    unlink('core');
    
    my $command = "$test_exec -s $proto$source_host$source_file";
    $errors = run_command($command, 2);
    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        $errors = "\n# Test failed\n# $command\n# " . $errors;
        ok($errors, 'success');
    }
}
push(@tests, "bad_buffer");

if(defined($ENV{FTP_TEST_RANDOMIZE}))
{
    shuffle(\@tests);
}

if(@ARGV)
{
    plan tests => scalar(@ARGV);

    foreach (@ARGV)
    {
        eval "&$tests[$_-1]";
    }
}
else
{
    plan tests => scalar(@tests), todo => \@todo;

    foreach (@tests)
    {
        eval "&$_";
    }
}
