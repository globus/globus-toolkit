#! /usr/bin/perl

use strict;
use File::Copy qw(copy);
use File::Temp qw(tempfile tempdir);
use Test::More;

my @tests = ();
my $current_test = "";
my $test_exec = "./import-cred-test";

sub test_import_data
{
    my $data = "";
    my ($cert, $key);

    open($cert, "testcred.cert");
    $data .= join("", <$cert>);

    open($key, "testcred.key");
    $data .= join("", <$key>);

    ok(system($test_exec, "-o", "0", "-i", $data) == 0, "$current_test");
}

sub test_import_file
{
    my ($fh, $tempfile);
    my $data = "";
    my ($cert, $key);

    ($fh, $tempfile) = tempfile();

    open($cert, "testcred.cert");
    $data .= join("", <$cert>);

    open($key, "testcred.key");
    $data .= join("", <$key>);

    $fh->write($data);

    ok(system($test_exec, "-o", "1", "-i", "p=$tempfile") == 0,
        "$current_test");
}

sub test_import_dir
{
    my $tempdir = tempdir(CLEANUP => 1);
    my $data = "";

    copy("testcred.cert", "$tempdir/hostcert.pem");
    chmod(0644, "$tempdir/hostcert.pem");

    copy("testcred.key", "$tempdir/hostkey.pem");
    chmod(0600, "$tempdir/hostkey.pem");

    ok(system($test_exec, "-o", "1", "-i", "p=$tempdir") == 0,
        "$current_test");
}

push(@tests, 'test_import_data');
push(@tests, 'test_import_file');
push(@tests, 'test_import_dir');

plan tests => scalar(@tests);

foreach (@tests)
{
    $current_test = $_;
    eval $current_test;
}
