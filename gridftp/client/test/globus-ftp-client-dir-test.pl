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


=head1 globus-ftp-client-size-test

Tests to exercise the size checking of the client library.

=cut

use strict;
use POSIX;
use Test;
use FtpTestLib;

my @tests;

my $gpath = $ENV{GLOBUS_LOCATION};

if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

my ($proto) = setup_proto();
my ($source_host, $source_file, $local_copy) = setup_remote_source();

my $source_url="$proto$source_host/~/gRidFTpTestdIR";

# remove the file if it is there
system("./globus-ftp-client-rmdir-test -s $source_file");
push(@tests, "run_check('./globus-ftp-client-mkdir-test', '-s', '');");
push(@tests, "run_check('./globus-ftp-client-rmdir-test', '-s', '');");
push(@tests, "run_check('./globus-ftp-client-put-test', '-d', '< /etc/group');");
push(@tests, "run_check('./globus-ftp-client-delete-test', '-s', '');");

sub run_check
{
    my ($errors,$rc) = ("",0);
    my $test_exec = shift;
    my $s_or_d = shift;
    my $input = shift;
    my $checked_size;

    unlink('core');

    my $command = "$test_exec $s_or_d $source_url $input 2>/dev/null";
    `$command`;
    $rc = $?;
    if($rc / 256 != 0)
    {
        $errors .= "\n# Test exited with " . $rc / 256;
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
