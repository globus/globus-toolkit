#! /usr/bin/env perl 

=head1 globus-ftp-client-size-test

Tests to exercise the size checking of the client library.

=cut

use strict;
use POSIX;
use Test;
use FtpTestLib;

my $test_exec = './globus-ftp-client-size-test';
my @tests;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my ($proto) = setup_proto();
my ($source_host, $source_file, $local_copy) = setup_remote_source();

sub check_size
{
    my ($errors,$rc) = ("",0);
    my ($old_proxy);
    my $src_url = shift;
    my $size = shift;
    my $checked_size;

    unlink('core');
    
    my $command = "$test_exec -s $src_url 2>/dev/null";
    $checked_size = `$command`;
    chomp($checked_size);
    $rc = $?;
    if($rc / 256 != 0 && $size >= 0)
    {
        $errors .= "\n# Test exited with " . $rc / 256;
    }
    if($size != -1 && $checked_size != $size)
    {
	$errors .= "\n# Size mismatch.";
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

if(source_is_remote())
{
    print "using remote source, skipping check_size()\n";
}
else
{
    
foreach('/etc/group', '/bin/sh', '/adsfadsfa')
{
    my $size = (stat($_))[7];
    if(!defined($size))
    {
	$size = -1;
    }

    push(@tests, "check_size('$proto$source_host$_', $size);");
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

}
