#! /usr/bin/env perl
#
# Test to exercise the "get" functionality of the Globus FTP client library.
#

use strict;
use POSIX;
use Test;
use FtpTestLib;
use Globus::URL;

my $test_exec = $ENV{GLOBUS_LOCATION} . '/test/' . 'globus-ftp-client-caching-get-test';
my @tests;
my @todo;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my ($test_url, $local_copy) = FtpTestLib::stage_source_url();

# Test #1-2. Basic functionality: Do a simple get (twice, caching the url)
# of $test_url (with and without a valid proxy).
# Compare the resulting file with the real file
# Success if program returns 0, files compare,
# and no core file is generated, or no valid proxy, and program returns 1.
sub basic_func
{
    my ($use_proxy) = (shift);
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    unlink('core');

    if($use_proxy == 0)
    {
        FtpTestLib::push_proxy("/dev/null");
    }
    $rc = system("$test_exec -s '$test_url' >'$tmpname' 2>/dev/null") / 256;
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
        my ($newtmp)=(POSIX::tmpnam());
	system("cat '$local_copy' '$local_copy' > $newtmp");

	$errors .= FtpTestLib::compare_local_files($newtmp, $tmpname);

	unlink($newtmp);	
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
    if($use_proxy == 0)
    {
        FtpTestLib::pop_proxy();
    }
}
push(@tests, "basic_func" . "(0);"); #Use invalid proxy
push(@tests, "basic_func" . "(1);"); #Use proxy

# Test #3: Bad URL: Do a simple get (twice, caching the URL)
# of a non-existent file.
# Success if program returns 1 and no core file is generated.
sub bad_url
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($bogus_url) = new Globus::URL($test_url);

    $bogus_url->{path} = "/no-such-file-here";
    unlink('core');

    $rc = system("$test_exec -s '".
		 $bogus_url->to_string()."' >/dev/null 2>/dev/null") / 256;
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
push(@tests, "bad_url");

# Test #4-44: Do a simple get (twice, caching the URL) of $test_url,
# aborting at each possible position. Note that not all aborts
# may be reached.
# Success if no core file is generated for all abort points. (we could use
# a stronger measure of success here)
sub abort_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("", 0);
    my ($abort_point) = shift;

    unlink('core', $tmpname);

    $rc = system("$test_exec -s '$test_url' -a $abort_point >/dev/null 2>/dev/null") / 256;
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

# Test #45-85. Restart functionality: Do a simple get (twice, caching the
# url) of $test_url, restarting at each plugin-possible point.
# Compare the resulting file with the real file
# Success if program returns 0, files compare,
# and no core file is generated.
sub restart_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($restart_point) = shift;

    unlink('core', $tmpname);

    $rc = system("$test_exec -s '$test_url' -r $restart_point > $tmpname 2>/dev/null") / 256;
    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }
    my ($newtmp)=(POSIX::tmpnam());
    system("cat '$local_copy' '$local_copy' > $newtmp");

    $errors .= FtpTestLib::compare_local_files($newtmp, $tmpname);

    unlink($newtmp);	

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
