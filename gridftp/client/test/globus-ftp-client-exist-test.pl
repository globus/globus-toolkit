#! /usr/bin/env perl 

=head1 globus-ftp-client-exist-test

Tests to exercise the existence checking of the client library.

=cut

use strict;
use POSIX;
use Test;
use FtpTestLib;

my $test_exec = './globus-ftp-client-exist-test';
my @tests;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

sub check_existence
{
    my ($errors,$rc) = ("",0);
    my ($old_proxy);
    my $src_url = shift;
    my $existence_rc = shift;

    unlink('core');

    my $command = "$test_exec -s $src_url >/dev/null 2>&1";
    $rc = system($command) / 256;
    if($rc != $existence_rc)
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

if(source_is_remote())
{
    print "using remote source, skipping check_existence()\n";
}
else
{
my $emptydir = POSIX::tmpnam();

mkdir $emptydir, 0755;

foreach('/etc/group', '/', '/etc', '/no-such-file', $emptydir)
{
    my $exists_rc = stat($_) ? 0 : 1;

    push(@tests, "check_existence('gsiftp://localhost$_', $exists_rc);");
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

rmdir $emptydir
}
