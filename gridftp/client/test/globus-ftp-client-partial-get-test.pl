#! /usr/bin/env perl 
#
# Test to exercise the "get" functionality of the Globus FTP client library
# using the partial file attribute.
#

use strict;
use POSIX;
use Test;
use FileHandle;

my $test_exec = $ENV{GLOBUS_LOCATION} . '/test/' . 'globus-ftp-client-partial-get-test';
my @tests;
my @todo;
my $fh = new FileHandle;
my $data;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

open($fh, "</etc/group");
my $size = (stat($fh))[7];
my $range = int($size / 4) . " " . int(2*int($size/4));
my $num_bytes = int(2*int($size/4)) - int($size / 4);
$data = join('', <$fh>);
close($fh);

# Test #1. Basic functionality: Do a get of the middle 1/4 of /etc/group from
# localhost.
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

    $rc = system("$test_exec -R $range >$tmpname 2>/dev/null") / 256;
    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
        $errors .= "\n# $test_exec -R $range";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }
    $rc = &compare_data($data, $tmpname);
	
    if($rc != 0)
    {
	$errors .= "\n# Differences between /etc/group and output.";
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
push(@tests, "basic_func();");

# Test #2-42: Do a partial get of /etc/group from localhost, aborting
# at each possible position. Note that not all aborts may be reached.
# Success if no core file is generated for all abort points. (we could use
# a stronger measure of success here)
sub abort_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("", 0);
    my ($abort_point) = shift;

    unlink('core', $tmpname);

    $rc = system("$test_exec -a $abort_point -R $range >/dev/null 2>/dev/null") / 256;
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
        $errors .= "\n# $test_exec -a $abort_point -R $range";
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

# Test #43-83. Restart functionality: Do a partial get of /etc/group from
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

    $rc = system("$test_exec -r $restart_point -R $range > $tmpname 2>/dev/null ") / 256;
    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }
    if(-r 'core')
    {
        $errors .= "\n# Core file generated.";
    }
    $rc = &compare_data($data, $tmpname);
    if($rc != 0)
    {
        $errors .= "\n# Differences found between files.";
    }

    if($errors eq "")
    {
        ok('success', 'success');
    }
    else
    {
        ok("\n# $test_exec -r $restart_point -R $range \n#$errors", 'success');
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

sub compare_data
{
    my($data, $filename) = @_;
    my($source_data, $dest_data, $start, $range, $end)=();
    my $fh = new FileHandle;
    my $rc = 0;
    my $stored_bytes = 0;
    open($fh, "<$filename");
    while(<$fh>)
    {
        s/(\[restart plugin\][^\n]*\n)//m;

	if(m/\[(\d*),(\d*)\]/)
	{
	    ($start,$end) = ($1, $2);
	    $range = $end - $start;
	    $stored_bytes += $range;
	    $source_data = substr($data, $start, $range);
	    read($fh, $dest_data, $range);
	    if($source_data ne $dest_data)
	    {
		$rc = 1;
	    }
	    $source_data = <$fh>;
	}
	elsif ($_ ne "")
	{
	    $rc = 1;
	}
    }
    if($stored_bytes < $num_bytes)
    {
        $rc = 1;
    }
    return $rc;
}
