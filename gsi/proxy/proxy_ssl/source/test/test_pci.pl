#!/usr/bin/perl

=pod

=head1 Tests for the globus gsi proxy_ssl code

Tests that exercise the functionality of creating an
ASN1 DER encoded PROXYCERTINFO extension to be placed
in an X509 certificate.

=cut

use strict;
use File::Basename;
use File::Compare;
use Test::More;

$ENV{PATH} = dirname($0) . ":.:" . $ENV{PATH};

my $test_prog = 'test_pci';

my @tests;
my @todo;
my $valgrind = "";
if (exists $ENV{VALGRIND})
{
    $valgrind = "valgrind --log-file=VALGRIND-$test_prog.log";
    if (exists $ENV{VALGRIND_OPTIONS})
    {
        $valgrind .= ' ' . $ENV{VALGRIND_OPTIONS};
    }
}

sub test_case
{
    my $test_index = shift;
    my $options = shift;
    my $testname = shift;

    ok(system("$valgrind $test_prog $options -out $test_prog.norm$test_index.der 1>$test_prog.log1.stdout")  == 0, "$testname.norm");
    ok(system("$valgrind $test_prog -in $test_prog.norm$test_index.der -out $test_prog.log$test_index.der 1> $test_prog.log2.stdout") == 0, "$testname.log");

    ok(File::Compare::compare("$test_prog.log$test_index.der",
                               "$test_prog.norm$test_index.der") == 0,
            "$testname.compareder");
    ok(File::Compare::compare("$test_prog.log1.stdout",
            "$test_prog.log2.stdout") == 0,
            "$testname.compare_stdout");

    &cleanup();
}

$SIG{'INT'}  = 'cleanup';
$SIG{'QUIT'} = 'cleanup';
$SIG{'KILL'} = 'cleanup';

plan tests => 4*5;      # 4 steps * 5 tests

test_case(1, "-path 10 -rest POLICYLANGUAGE POLICY", "path10-policy");
test_case(2, "-path 10", "path10");
test_case(3, "-path 0 -rest POLICYLANGUAGE POLICY", "path0-policy");
test_case(4, "-rest POLICYLANGUAGE POLICY", "policy");
test_case(5, "-out test_pci5.der", "default");

sub cleanup
{
    if (-e "$test_prog.log1.stdout")
    {
        unlink("$test_prog.log1.stdout");
    }
    if (-e "$test_prog.log2.stdout")
    {
        unlink("$test_prog.log2.stdout");
    }
    
    if (-e "$test_prog.log1.stderr")
    {
        unlink("$test_prog.log1.stderr");
    }
    if (-e "$test_prog.log2.stderr")
    {
        unlink("$test_prog.log2.stderr");
    }
}

END {
    &cleanup();
}
