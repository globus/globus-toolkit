#! /usr/bin/env perl 
#
# Test to exercise the "get" functionality of the Globus FTP client
# library allowing a user-specified authorized certificate name.
#

use strict;
use POSIX;
use Test;
use FtpTestLib;

my $test_exec = './globus-ftp-client-user-auth-test';
my @tests;
my @todo;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my ($source_host, $source_file, $local_copy) = setup_remote_source();

# Test #1. User specifies the correct authorization information.
# Success if program returns 0, files compare,
# and no core file is generated, or no valid proxy, and program returns 1.
sub correct_auth
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($hostname) = ();
    unlink('core', $tmpname);

    if(exists $ENV{GLOBUS_HOSTNAME})
    {
        $hostname = $ENV{GLOBUS_HOSTNAME};
    }
    else
    {
        $hostname = `hostname`;
    }
    chomp($hostname);
    
    my $command = "$test_exec -s gsiftp://$source_host$source_file -A 'host\@$hostname' >$tmpname 2>/dev/null";
    $rc = system($command) / 256;
    if($rc != 0)
    {
        $errors .= "\n# Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }
    
    my $diffs = `diff $local_copy $tmpname | sed -e 's/^/# /'`;
        
    if($? != 0)
    {
        $errors .= "\n# Differences between /etc/group and output.";
        $errors .= "$diffs";
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
    unlink($tmpname);
}
push(@tests, "correct_auth");

# Test #2: User specifies incorrect authorization information.
# Success if program returns 1 and no core file is generated.
sub incorrect_auth
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($hostname) = ("googly_goodness");
    unlink('core', $tmpname);

    my $command = "$test_exec -s gsiftp://$source_host$source_file -A 'host\@$hostname' >$tmpname 2>/dev/null";
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
    unlink($tmpname);
}
push(@tests, "incorrect_auth");

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
