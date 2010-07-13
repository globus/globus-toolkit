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
# in extended block mode
#

use strict;
use POSIX;
use Test;
use FtpTestLib;
use FileHandle;

my $test_exec = './globus-ftp-client-extended-get-caching-test';
my @tests;
my @todo;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my ($proto) = setup_proto();
my ($source_host, $testfile, $local_copy) = setup_remote_source(1);

my $handle = new FileHandle;

open($handle, "<$local_copy");
my $test_data=join('', <$handle>);
close($handle);
my $num_bytes=length($test_data);

# Test #1-10. Basic functionality: Do a get of $testfile to
# a new unique file name on localhost, varying parallelism level.
# Compare the resulting file with the real file
# Success if program returns 0, files compare,
# and no core file is generated.
sub basic_func
{
    my ($parallelism) = (shift);
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    unlink($tmpname);

    my $command = "$test_exec -P $parallelism -s $proto$source_host$testfile >$tmpname 2>/dev/null";
    $errors = run_command($command, 0);
    if($errors eq "" && 0 != &compare_data($test_data, $tmpname))
    {
	$errors .= "\n# Differences between $testfile and output.";
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
for(my $par = 1; $par <= 10; $par++)
{
    push(@tests, "basic_func($par);");
}

# Test #11: Bad URL: Do a simple get of a non-existent file from localhost.
# Success if program returns 1 and no core file is generated.
sub bad_url
{
    my ($errors,$rc) = ("",0);

    my $command = "$test_exec -s $proto$source_host/no-such-file-here >/dev/null  2>/dev/null";
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

# Test #12-421: Do a get of $testfile from localhost, aborting at each
# possible position, with parallelism between 1 and 10. Note that not
# all aborts may be reached.  Success if no core file is generated for
# all abort points. (we could use a stronger measure of success here)
sub abort_test
{
    my ($errors,$rc) = ("", 0);
    my ($abort_point) = shift;
    my ($par) = shift;

    my $command = "$test_exec -P $par -a $abort_point -s $proto$source_host$testfile >/dev/null 2>/dev/null";
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
    for(my $j = 1; $j <= 10 ; $j++)
    {
	push(@tests, "abort_test($i,$j);");
    }
}

# Test #422-851. Restart functionality: Do a simple get of $testfile from
# localhost, restarting at each plugin-possible point.
# Compare the resulting file with the real file
# Success if program returns 0, files compare,
# and no core file is generated.
sub restart_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);
    my ($restart_point) = shift;
    my ($par) = shift;

    unlink($tmpname);

    my $command = "$test_exec -P $par -r $restart_point -s $proto$source_host$testfile >$tmpname 2>/dev/null";
    $errors = run_command($command, 0);
    if($errors eq "" && 0 != &compare_data($test_data, $tmpname))
    {
        $errors .= "\n# Differences between $testfile and output.";
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
    for(my $j = 1; $j <= 10; $j++)
    {
        push(@tests, "restart_test($i, $j);");
    }
}

=head2 I<perf_test> (Test 852)

Do an extended get of $testfile, enabling perf_plugin

=back

=cut
sub perf_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    my $command = "$test_exec -s $proto$source_host$testfile -M >$tmpname 2>/dev/null";
    $errors = run_command($command, 0);
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

push(@tests, "perf_test();");

=head2 I<throughput_test> (Test 853)

Do an extended get of $testfile, enabling throughput_plugin

=back

=cut
sub throughput_test
{
    my $tmpname = POSIX::tmpnam();
    my ($errors,$rc) = ("",0);

    my $command = "$test_exec -s $proto$source_host$testfile -T >$tmpname 2>/dev/null";
    $errors = run_command($command, 0);
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

push(@tests, "throughput_test();");

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
    my($source_data, $dest_data, $start, $range)=();
    my $fh = new FileHandle;
    my $rc = 0;
    my $stored_bytes = 0;
    open($fh, "<$filename");

    while(<$fh>)
    {
        s/(\[restart plugin\][^\n]*\n)//m;

	if(m/\[(\d*),(\d*)\]/)
	{
	    ($start,$range) = ($1, $2);
	    $stored_bytes += $range;
	    $source_data = substr($data, $start, $range);
	    read($fh, $dest_data, $range);
	    if($start == 0 && $range == 0)
	    {
	        $source_data = <$fh>;
	        next;
	    }
	    if($source_data ne $dest_data)
	    {
	        print "wrong data\n";
		$rc = 1;
		exit(1);
	    }
	    $source_data = <$fh>;
	}
	elsif($_ ne "")
	{
	    print "missing block header: '$_'\n";
	    $rc = 1;
	}
    }
    if($stored_bytes < $num_bytes)
    {
        print "wrong amt of data\n";
        $rc = 1;
    }
    return $rc;
}
