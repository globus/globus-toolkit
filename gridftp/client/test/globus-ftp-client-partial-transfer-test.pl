#! /usr/bin/env perl
#
# Test to exercise the "transfer" functionality of the Globus FTP client library
# using the partial file attribute.
#

use strict;
use POSIX;
use Test;
use FileHandle;

my $test_exec = $ENV{GLOBUS_LOCATION} . "/test/" . 'globus-ftp-client-partial-transfer-test';
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
    my $tmpname2 = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($old_proxy);
    my $newfile = new FileHandle;
    my $offset = shift;
    my ($source_data, $dest_data) = ("", "");

    unlink('core');

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
           " -s gsiftp://localhost$tmpname2 -d gsiftp://localhost$tmpname";
    print `$cmd`;

    $rc = $? >> 8;
    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
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
        ok("\n# $test_exec -R $offset ". int(100+$offset) . " -s gsiftp://localhost$tmpname2 -d gsiftp://localhost$tmpname \n$errors", 'success');
    }
    unlink($tmpname, $tmpname2);
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

