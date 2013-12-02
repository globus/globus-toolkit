#!/usr/bin/perl

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

use strict;
use Getopt::Long
require 5.8.0;
use vars qw(@tests);

my $dir = undef;

sub test_exec
{
    my ($harness, $test_file) = @_;
    if ($test_file =~ /.pl$/) {
        if ($dir) {
            return "$dir/$test_file";
        } else {
            return undef;
        }
    } else {
        my @cmd;
        my $valgrind="";
        if (exists $ENV{VALGRIND})
        {
            push(@cmd, 'valgrind');
            push(@cmd, "--log-file=VALGRIND-$test_file.log");
            if (exists $ENV{VALGRIND_OPTIONS})
            {
                for my $opt (split(/\s+/, $ENV{VALGRIND_OPTIONS})) {
                    if ($opt ne '') {
                        push(@cmd, $opt);
                    }
                }
            }
        }
        push(@cmd, "$test_file");
        return \@cmd;
    }
}

my $harness_class = "TAP::Harness";

if (!GetOptions("harness=s" => \$harness_class,
                "dir=s" => \$dir))
{
    print STDERR "Usage: $0 [-harness CLASSNAME] [-dir TESTDIR]\n";
    exit(1);
}
            
eval "use $harness_class";

my $harness_args = {'exec' => \&test_exec, 'merge' => 1};
$harness_args->{'lib'} = [ $dir ] if ($dir);
my $harness = $harness_class->new($harness_args);

$ENV{PATH} = ".:" . $ENV{PATH};
$ENV{PATH} = "${dir}:" . $ENV{PATH} if ($dir);

@tests = qw(
        fifo_test
        globus_args_scan_test
        globus_error_construct_string_test
        globus_libc_setenv_test
        globus_url_test
        hash_test
        list_test
        memory_test
        module_test
        off_t_test
        poll_test
        strptime_test
        thread_test
        timedwait_test
        uuid_test
);

$harness->runtests(@tests);
