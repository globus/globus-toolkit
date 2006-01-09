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
# Test to exercise the "transfer" functionality of the Globus FTP client library
# using the partial file attribute.
#

use strict;
use POSIX;
use Test;
use FileHandle;
use FtpTestLib;

my $test_exec = './globus-ftp-client-partial-transfer-test';
my @tests;
my @todo;
my $data;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my ($proto) = setup_proto();
my ($source_host, $source_file, $local_copy) = setup_remote_source();
my ($dest_host, $dest_file) = setup_remote_dest();

# Test #1-3. Basic functionality: create a dummy file in /tmp; modify
# that file remotely using partial file put; make sure the file is
# what it should be.
# Test with offset at 0, offset in the middle of the file, and offset
# past the edge of the file.
# Success if program returns 0, files compare, and no core file
# is generated.
sub basic_func
{
    my $tmpname = POSIX::tmpnam();
    my $tmpname2 = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my $newfile = new FileHandle;
    my $offset = shift;
    my ($source_data, $dest_data) = ("", "");

    if(defined($ENV{'FTP_TEST_DEST_FILE'}))
    {
        $tmpname=$ENV{'FTP_TEST_DEST_FILE'};
        unlink($tmpname);
    }
    if(defined($ENV{'FTP_TEST_DEST_FILE2'}))
    {
        $tmpname2=$ENV{'FTP_TEST_DEST_FILE2'};
        unlink($tmpname2);
    }
    # Create initial contents of the source file.
    for(my $i = 0; $i < 8192; $i++)
    {
	$source_data .= chr(($i % 26) + ord("a"));
    }
    $source_data .= "\n";

    # Create initial contents of the dest file.
    for(my $i = 0; $i < 4096; $i++)
    {
        my $foo = 10 - $i % 10;
	$dest_data .= $foo;
    }
    $dest_data .= "\n";

    # put files in their appropriate locations
    open($newfile, ">>$tmpname2");
    print $newfile $source_data;
    close $newfile;

    open($newfile, ">>$tmpname");
    print $newfile $dest_data;
    close $newfile;

    if($offset > length($dest_data))
    {
        substr($dest_data,
	       length($dest_data),
	       $offset - length($dest_data),
	       chr(0) x ($offset - length($dest_data) + 100));
    }
    substr($dest_data, $offset, 100, substr($source_data, $offset, 100));

    my $cmd = "$test_exec -R $offset " .int(100+$offset).
           " -s $proto$source_host$tmpname2 -d $proto$dest_host$tmpname";
    print `$cmd`;

    $rc = $?;
    if($rc / 256 != 0)
    {
        $errors .= "\n# Test exited with " . $rc / 256;
    }

    open($newfile, "<$tmpname");
    my $result_data = join('', <$newfile>);

    if($result_data ne $dest_data)
    {
	$errors .= "\n# Different from expected output.";
        $errors .= "\n# expected '$dest_data'";
        $errors .= "\n# got '$result_data'";
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        ok("\n# $cmd\n$errors", 'success');
    }
    unlink($tmpname, $tmpname2);
}

if(source_is_remote() || dest_is_remote())
{
    print "using remote source, skipping basic_func()\n";
}
else
{
    
    push(@tests, "basic_func(0);");
    push(@tests, "basic_func(100);");
    push(@tests, "basic_func(5000);");

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
    
}
