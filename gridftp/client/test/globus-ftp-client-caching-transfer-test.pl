#! /usr/bin/env perl
#
# Test to exercise the "3rd party transfer" functionality of the Globus
# FTP client library using URL caching.
#

use strict;
use POSIX;
use Test;

my $test_exec = $ENV{GLOBUS_LOCATION} . '/test/' . 'globus-ftp-client-caching-transfer-test';
my @tests;
my @todo;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

# Test #1-2. Basic functionality: Do two transfers of /etc/group to/from
# localhost (with and without a valid proxy) using URL caching.
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
    $rc = system("$test_exec -d 'gsiftp://localhost/$tmpname' 2>/dev/null") / 256;
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
    	my $diffs = `diff /etc/group $tmpname 2>&1 | sed -e 's/^/# /'`;
	
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

# Test #3: Bad URL: Do a 3rd party transfer of a using a non-existent
# file from localhost twice using URL caching.
# Success if program returns 1 and no core file is generated.
sub bad_url_src
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    unlink('core', $tmpname);

    $rc = system("$test_exec -s 'gsiftp://localhost/no-such-file-here' -d 'gsiftp://localhost/$tmpname' >/dev/null 2>/dev/null") / 256;
    if($rc != 2)
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
push(@tests, "bad_url_src");

# Test #4: Bad URL: Do a 3rd party transfer of an unwritable location as the
# destination twice using URL caching.
# Success if program returns 1 and no core file is generated.
sub bad_url_dest
{
    my ($errors,$rc) = ("",0);

    $rc = system("$test_exec -d 'gsiftp://localhost/no-such-file-here' >/dev/null 2>/dev/null") / 256;
    if($rc != 2)
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
}
push(@tests, "bad_url_dest");

# Test #5-45: Do a simple transfer of /etc/group to/from localhost twice,
# using caching, and aborting at each possible position. Note that not all
# aborts may be reached.
# Success if no core file is generated for all abort points. (we could use
# a stronger measure of success here)
sub abort_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("", 0);
    my ($abort_point) = shift;

    unlink('core', $tmpname);

    $rc = system("$test_exec -a $abort_point -d gsiftp://localhost/$tmpname>/dev/null 2>/dev/null") / 256;
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
        ok("\n# $test_exec -a $abort_point\n#$errors", 'success');
    }
    unlink($tmpname);
}
for(my $i = 1; $i <= 41; $i++)
{
    push(@tests, "abort_test($i);");
}

# Test #46-86. Restart functionality: Do a simple transfer of /etc/group
# to/from localhost twice using URL caching, restarting at each
# plugin-possible point. Compare the resulting file with the real file.
# Success if program returns 0, files compare,
# and no core file is generated.
sub restart_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($restart_point) = shift;

    unlink('core', $tmpname);

    $rc = system("$test_exec -r $restart_point -d 'gsiftp://localhost/$tmpname' >/dev/null 2>/dev/null") / 256;
    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }
    my $diffs = `diff /etc/group $tmpname 2>&1 | sed -e 's/^/#/'`;
    if($diffs ne "")
    {
        $errors .= "\n# Differences between /etc/group and output.";
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
