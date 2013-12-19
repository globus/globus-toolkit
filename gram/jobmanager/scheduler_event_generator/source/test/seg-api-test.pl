#! /usr/bin/perl

use Test::More;
use File::Basename;
use File::Compare;
use File::Temp 'tempdir';

plan tests => 2;

my $testtmp = tempdir( CLEANUP => 1 );
my $test_exe = "seg-api-test";
my $file = dirname($0)."/seg_api_test_data.txt";

ok(system("./$test_exe $file > $testtmp/output") == 0, $test_exe);
ok(File::Compare::compare("$testtmp/output", $file) == 0, "$test_exe compare");
