#!/usr/bin/env perl

my $test_prog = './run-openssl-error-tests.pl';

# Accomodate running tests on Windows platform - remove leading './'
if ("$^O" =~ /win32/i)
{
   $test_prog =~ s/(.\/)//;
}

my $res = system("$test_prog");
exit ( $res != 0 );


