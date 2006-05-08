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
# Test to exercise the "put" functionality of the Globus FTP client library
# using the partial file attribute.
#

use strict;
use POSIX;
use Test;
use FileHandle;
use FtpTestLib;
use File::Spec;

my $test_exec = './globus-ftp-client-partial-put-test';
my @tests;
my @todo;
my $fh = new FileHandle;
my $data;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my ($proto) = setup_proto();
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
    my ($errors,$rc) = ("",0);
    my ($old_proxy);
    my $newfile = new FileHandle;
    my $offset = shift;
    my $data = "";
    unlink($dest_file);

    # Create a file of known contents, for the partial update.
    open($newfile, ">$dest_file");
    for(my $i = 0; $i < 4096; $i++)
    {
	$data .= $i % 10;
    }
    $data .= "\n";
    print $newfile $data;
    close $newfile;
    
    my $command = "$test_exec -R $offset -d $proto$dest_host$dest_file -p >".File::Spec::->devnull()."2>&1";
    open($newfile, "|$command");
    my $i = $offset;
    if($offset > 4096)
    {
        for($a = 4096; $a < $offset; $a++)
	{
	    $data .=  chr(0);
	}
    }
    for(my $a = ord("a"); $a < ord("z"); $a++)
    {
        print $newfile chr($a);
	substr($data, $i++, 1, chr($a));
    }
    close($newfile);

    $rc = $?;
    if($rc / 256 != 0)
    {
        $errors .= "\n# Test exited with " . $rc / 256;
    }

    open($newfile, "|diff - $dest_file");
    print $newfile $data;
    close($newfile);
    $rc = $? >> 8;
    if($rc != 0)
    {
	$errors .= "\n# Different from expected output.";
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
    unlink($dest_file);
}

if(source_is_remote())
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
