#! /usr/bin/perl

use strict;
use warnings;

use Getopt::Long;
use IPC::Open3;
use Test::More;
use Symbol qw(gensym);
use File::Temp qw/tempdir tempfile/;
use File::Compare qw/compare/;

require 5.8.0;

my $subject = $ENV{GLOBUS_FTP_SUBJECT};
my $contact = $ENV{GLOBUS_FTP_CONTACT};
my $tempdir = tempdir(CLEANUP => 1);

my $result = GetOptions("-subject=s" => \$subject, "-contact=s" => \$contact);

if ((!$subject) || (!$contact))
{
    print STDERR "Required -subject and -contact command-line options\n";
    exit(77);
}

sub random_file
{
    my $size = shift;
    my ($fh, $filename) = tempfile(DIR => $tempdir);
    my @chars = ("a".."z", "A".."Z", "0".."9");

    print $fh $chars[rand(@chars)] for 1..$size; 
    $fh->flush();

    return ($fh, $filename);
}

sub read_test
{
    my $random_file = random_file(128);
    my ($pid, $infd, $outfd, $errfd);
    $errfd = gensym;

    $pid = open3($infd, $outfd, $errfd,
        'globus_gridftp_driver_test', '-r',
        '-f', "$random_file.local",
        '-c', "$contact/$random_file",
        '-subject', $subject);
    $infd->close();
    waitpid($pid, 0);

    ok($? == 0, "globus_gridftp_driver_test -r exits with $?");
    ok(compare($random_file, "$random_file.local") == 0,
        "File compares with remote original");
}

sub write_test
{
    my $random_file = random_file(128);
    my ($pid, $infd, $outfd, $errfd);
    $errfd = gensym;

    $pid = open3($infd, $outfd, $errfd,
        'globus_gridftp_driver_test', '-w',
        '-f', "$random_file",
        '-c', "$contact/$random_file.remote",
        '-subject', $subject);
    $infd->close();
    waitpid($pid, 0);

    ok($? == 0, "globus_gridftp_driver_test -w exits with $?");
    ok(compare($random_file, "$random_file.remote") == 0,
        "File compares with remote");
}

sub append_test
{
    my $random_file = random_file(128);
    my ($pid, $infd, $outfd, $errfd);
    $errfd = gensym;

    $pid = open3($infd, $outfd, $errfd,
        'globus_gridftp_driver_test', '-w', '-a',
        '-f', "$random_file",
        '-c', "$contact/$random_file.remote",
        '-subject', $subject);
    $infd->close();
    waitpid($pid, 0);

    ok($? == 0, "globus_gridftp_driver_test -a exits with $?");
    ok(compare($random_file, "$random_file.remote") == 0,
        "File compares with remote");

    $errfd = gensym;

    $pid = open3($infd, $outfd, $errfd,
        'globus_gridftp_driver_test', '-w', '-a',
        '-f', "$random_file",
        '-c', "$contact/$random_file.remote",
        '-subject', $subject);
    $infd->close();
    waitpid($pid, 0);

    open(my $random_fd, "+<", $random_file);
    my $random_data;
    local($/);
    $random_data = <$random_fd>;
    print $random_fd $random_data;
    $random_fd->flush();

    ok($? == 0, "2nd globus_gridftp_driver_test -a exits with $?");
    ok(compare($random_file, "$random_file.remote") == 0,
        "File compares with appended remote");
}

plan tests => 8;
SKIP: {
    skip "No GridFTP server for tests", 2 unless ($subject && $contact);
    read_test();
    write_test();
    append_test();
}
