#! /usr/bin/env perl
#
# Test to exercise the "put" functionality of the Globus FTP client library
# using the partial file attribute.
#

use strict;
use POSIX;
use Test;
use FileHandle;

my $test_exec = $ENV{GLOBUS_LOCATION} . "/test/" . 'globus-ftp-client-partial-put-test';
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
    my ($errors,$rc) = ("",0);
    my ($old_proxy);
    my $newfile = new FileHandle;
    my $offset = shift;
    my $data = "";
    unlink('core', $tmpname);

    # Create a file of known contents, for the partial update.
    open($newfile, ">$tmpname");
    for(my $i = 0; $i < 4096; $i++)
    {
	$data .= $i % 10;
    }
    $data .= "\n";
    print $newfile $data;
    close $newfile;

    open($newfile, "|$test_exec -R $offset -d gsiftp://localhost$tmpname -p >/dev/null 2>&1");
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

    $rc = $? >> 8;
    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }

    open($newfile, "|diff - $tmpname");
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
        ok($errors, 'success');
    }
    unlink($tmpname);
}
push(@tests, "basic_func(0);");
push(@tests, "basic_func(100);");
push(@tests, "basic_func(5000);");

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
    eval "&$_";
}

