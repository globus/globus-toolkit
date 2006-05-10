#! /usr/bin/env perl 

# 
# Copyright 1999-2006 University of Chicago
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 

#
# Test to exercise the "get" functionality of the Globus FTP client library
# using the partial file attribute.
#

use strict;
use POSIX;
use Test;
use FileHandle;
use FtpTestLib;

my $test_exec = './globus-ftp-client-partial-get-test';
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

my ($proto) = setup_proto();
my ($source_host, $source_file, $local_copy) = setup_remote_source();

open($fh, "<$local_copy");
binmode($fh);
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

    unlink($tmpname);

    my $command = "$test_exec -R $range -s $proto$source_host$source_file";
    $errors = run_command($command, 0, $tmpname);
    if($errors eq "")
    {
        $rc = &compare_data($data, $tmpname);
        if($rc != 0)
        {
        	$errors .= "\n# Differences between $local_copy and output.";
        }
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
push(@tests, "basic_func();");

# Test #2-42: Do a partial get of /etc/group from localhost, aborting
# at each possible position. Note that not all aborts may be reached.
# Success if no core file is generated for all abort points. (we could use
# a stronger measure of success here)
sub abort_test
{
    my ($errors,$rc) = ("", 0);
    my ($abort_point) = shift;

    my $command = "$test_exec -a $abort_point -R $range -s $proto$source_host$source_file";
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

    unlink($tmpname);

    my $command = "$test_exec -r $restart_point -R $range -s $proto$source_host$source_file";
    $errors = run_command($command, 0, $tmpname);
    if($errors eq "")
    {
        $rc = &compare_data($data, $tmpname);
        if($rc != 0)
        {
            $errors .= "\n# Differences found between files.";
        }
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

sub compare_data
{
    my($data, $filename) = @_;
    my($source_data, $dest_data, $start, $range, $end)=();
    my $fh = new FileHandle;
    my $rc = 0;
    my $stored_bytes = 0;
    open($fh, "<$filename");
    binmode($fh);
    while(<$fh>)
    {
        s/(\[restart plugin\].*?\n)//m;

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
