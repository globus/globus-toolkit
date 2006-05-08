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
# Test to exercise the "get" functionality of the Globus FTP client library
# using different number of buffer registrations than the simple_get
#

use strict;
use POSIX;
use Test;
use FtpTestLib;
use File::Spec;

my $test_exec = './globus-ftp-client-multiple-block-get-test';
my @tests;
my @todo;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my ($proto) = setup_proto();
my ($source_host, $source_file, $local_copy) = setup_remote_source();

# Test #1-2. Basic functionality: Do a get of /etc/group from
# localhost (with and without a valid proxy).
# Compare the resulting file with the real file
# Success if program returns 0, files compare,
# and no core file is generated, or no valid proxy, and program returns 1.
sub basic_func
{
    my ($use_proxy) = (shift);
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($old_proxy);

    unlink($tmpname);

    $old_proxy=$ENV{'X509_USER_PROXY'}; 
    if($use_proxy == 0)
    {
        $ENV{'X509_USER_PROXY'} = File::Spec::->devnull();
    }
    my $command = "$test_exec -s '$proto$source_host$source_file'";
    $errors = run_command($command, $use_proxy ? 0 : -1, $tmpname);
    if($errors eq "" && $use_proxy)
    {
        $errors .= compare_local_files($local_copy, $tmpname);
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
    if((!$use_proxy) && defined($old_proxy))
    {
	$ENV{'X509_USER_PROXY'} = $old_proxy;
    }
    elsif((!$use_proxy))
    {
        delete $ENV{'X509_USER_PROXY'};
    }
}
push(@tests, "basic_func" . "(0);") unless $proto ne "gsiftp://"; #Use invalid proxy
push(@tests, "basic_func" . "(1);"); #Use proxy

# Test #3: Bad URL: Do a get of a non-existent file from localhost.
# Success if program returns 1 and no core file is generated.
sub bad_url
{
    my ($errors,$rc) = ("",0);

    my $command = "$test_exec -s '$proto$source_host/no-such-file-here'";
    $errors = run_command($command, 1);
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
push(@tests, "bad_url");

# Test #4-44: Do a get of /etc/group from localhost, aborting
# at each possible position. Note that not all aborts may be reached.
# Success if no core file is generated for all abort points. (we could use
# a stronger measure of success here)
sub abort_test
{
    my ($errors,$rc) = ("", 0);
    my ($abort_point) = shift;
    
    my $command = "$test_exec -a $abort_point -s '$proto$source_host$source_file'";
    $errors = run_command($command, -2);
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
for(my $i = 1; $i <= 43; $i++)
{
    push(@tests, "abort_test($i);");
}

# Test #45-85. Restart functionality: Do a get of /etc/group from
# localhost, restarting at each plugin-possible point.
# Compare the resulting file with the real file
# Success if program returns 0, files compare,
# and no core file is generated.
sub restart_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($restart_point) = shift;

    unlink($tmpname);

    my $command = "$test_exec -r $restart_point -s '$proto$source_host$source_file'";
    $errors = run_command($command, 0, $tmpname);
    if($errors eq "")
    {
        $errors .= compare_local_files($local_copy, $tmpname);
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
for(my $i = 1; $i <= 43; $i++)
{
    push(@tests, "restart_test($i);");
}

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
