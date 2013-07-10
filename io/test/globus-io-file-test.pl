#!/usr/bin/env perl

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


=pod

=head1 Tests for the globus IO file code

    Tests to exercise the file IO functionality of the globus IO library.

=cut

use strict;
use Test::More;
use File::Compare;

my $test_prog = 'globus_io_file_test';
my @tests;
my $valgrind="";

if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-$test_prog.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

sub basic_func
{
    my ($errors,$rc) = ("",0);
    my $ok=0;
    
    $rc = system("$valgrind ./$test_prog 1>$test_prog.log.stdout 2>$test_prog.log.stderr") / 256;

    if($rc != 0)
    {
        $errors .= "Test exited with $rc. ";
    }

    ok(($rc == 0) && 
        (File::Compare::compare("$test_prog.log.stdout", "/etc/group") == 0) &&
        (! -s "$test_prog.stderr") && (($ok=1) ==1),
        $test_prog);

    if($ok == 1)
    {
        if( -e "$test_prog.log.stdout" )
        {
            unlink("$test_prog.log.stdout");
        }
        
        if( -e "$test_prog.log.stderr" )
        {
            unlink("$test_prog.log.stderr");
        } 
    }
}

sub sig_handler
{
    if( -e "$test_prog.log.stdout" )
    {
        unlink("$test_prog.log.stdout");
    }

    if( -e "$test_prog.log.stderr" )
    {
        unlink("$test_prog.log.stderr");
    }
}

$SIG{'INT'}  = 'sig_handler';
$SIG{'QUIT'} = 'sig_handler';
$SIG{'KILL'} = 'sig_handler';

push(@tests, "basic_func();");
plan tests => scalar(@tests);

foreach (@tests)
{
    eval "&$_";
}
