#! /usr/bin/env perl 
#
# Test to exercise the "get" functionality of the Globus FTP client library
# using different number of buffer registrations than the simple_get
#

use strict;
use POSIX;
use Test;

my $test_exec = $ENV{GLOBUS_LOCATION} . '/test/' . 'globus-ftp-client-multiple-block-get-test';
my @tests;
my @todo;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

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

    unlink('core', $tmpname);

    $old_proxy=$ENV{'X509_USER_PROXY'}; 
    if($use_proxy == 0)
    {
        $ENV{'X509_USER_PROXY'} = "/dev/null";
    }
    $rc = system("$test_exec >$tmpname 2>/dev/null") / 256;
    if(($use_proxy && $rc != 0) || (!$use_proxy && $rc == 0))
    {
        $errors .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }
    if($use_proxy)
    {
    	my $diffs = `diff /etc/group $tmpname | sed -e 's/^/# /'`;
	
	if($diffs ne "")
	{
	    $errors .= "\n# Differences between /etc/group and output.";
	    $errors .= "$diffs";
	}
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
    if((!$use_proxy) && defined($old_proxy))
    {
	$ENV{'X509_USER_PROXY'} = $old_proxy;
    }
    elsif((!$use_proxy))
    {
        delete $ENV{'X509_USER_PROXY'};
    }
}
push(@tests, "basic_func" . "(0);"); #Use invalid proxy
push(@tests, "basic_func" . "(1);"); #Use proxy

# Test #3: Bad URL: Do a get of a non-existent file from localhost.
# Success if program returns 1 and no core file is generated.
sub bad_url
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    unlink('core', $tmpname);

    $rc = system("$test_exec -s 'gsiftp://localhost/no-such-file-here' >/dev/null 2>/dev/null") / 256;
    if($rc != 1)
    {
        $errors .= "\n# Test exited with $rc.";
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
        ok($errors, 'success');
    }
    unlink($tmpname);
}
push(@tests, "bad_url");

# Test #4-44: Do a get of /etc/group from localhost, aborting
# at each possible position. Note that not all aborts may be reached.
# Success if no core file is generated for all abort points. (we could use
# a stronger measure of success here)
sub abort_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("", 0);
    my ($abort_point) = shift;

    unlink('core', $tmpname);

    $rc = system("$test_exec -a $abort_point >/dev/null 2>/dev/null") / 256;
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
        ok($errors, 'success');
    }
    unlink($tmpname);
}
for(my $i = 1; $i <= 41; $i++)
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

    unlink('core', $tmpname);

    $rc = system("$test_exec -r $restart_point > $tmpname 2>/dev/null") / 256;
    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }
    my $diffs = `grep -v '\\[restart plugin\\]' $tmpname | diff /etc/group - | sed -e 's/^/#/'`;
    if($diffs ne "")
    {
        $errors .= "\n# Differences between /etc/group and output.\n$diffs";
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        ok("\n# $test_exec -r $restart_point\n#$errors", 'success');
    }
    unlink($tmpname);
}
for(my $i = 1; $i <= 41; $i++)
{
    push(@tests, "restart_test($i);");
}

# Now that the tests are defined, set up the Test to deal with them.
plan tests => scalar(@tests), todo => \@todo;

# And run them all.
foreach (@tests)
{
    eval "&$_";
}
