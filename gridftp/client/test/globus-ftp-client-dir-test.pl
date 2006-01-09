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


=head1 globus-ftp-client-size-test

Tests to exercise the size checking of the client library.

=cut

use strict;
use POSIX;
use Test;
use FtpTestLib;

my @tests;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my ($proto) = setup_proto();
my ($source_host, $source_file, $local_copy) = setup_remote_source();

my $source_url="$proto$source_host/~/gRidFTpTestdIR";

# remove the file if it is there
system("./globus-ftp-client-rmdir-test -s $source_file");
push(@tests, "run_check('./globus-ftp-client-mkdir-test', '-s', '');");
push(@tests, "run_check('./globus-ftp-client-rmdir-test', '-s', '');");
push(@tests, "run_check('./globus-ftp-client-put-test', '-d', '< /etc/group');");
push(@tests, "run_check('./globus-ftp-client-delete-test', '-s', '');");

sub run_check
{
    my ($errors,$rc) = ("",0);
    my $test_exec = shift;
    my $s_or_d = shift;
    my $input = shift;
    my $checked_size;

    unlink('core');

    my $command = "$test_exec $s_or_d $source_url $input 2>/dev/null";
    `$command`;
    $rc = $?;
    if($rc / 256 != 0)
    {
        $errors .= "\n# Test exited with " . $rc / 256;
    }

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
    plan tests => scalar(@tests);

    foreach (@tests)
    {
        eval "&$_";
    }
}
