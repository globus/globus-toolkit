#! /usr/bin/env perl 

=head1 globus-ftp-client-lingering-get-test

Tests to exercise the deactivation of the client and control libraries while
an operation is left in progress.

=cut

use strict;
use POSIX;
use Test;
use FtpTestLib;

my $test_exec = './globus-ftp-client-lingering-get-test';
my @tests;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

=head1 I<lingering_get> (Test 1)

Do a get of $test_url. But don't deal with data block before deactivating
the client library.

=cut

my ($source_host, $source_file, $local_copy) = setup_remote_source();

sub lingering_get
{
    my ($errors,$rc) = ("",0);
    my ($old_proxy);

    unlink('core');
    
    my $command = "$test_exec -s gsiftp://$source_host$source_file >/dev/null 2>&1";
    $rc = system($command) / 256;
    if($rc != 1)
    {
        $errors .= "\n# Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
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
push(@tests, "lingering_get();");

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
