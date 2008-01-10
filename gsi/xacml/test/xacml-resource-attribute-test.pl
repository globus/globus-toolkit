#!/usr/bin/env perl

use strict;
use Test;

my $test_prog = './xacml-resource-attribute-test';

if ($ENV{VALGRIND})
{
    system("valgrind --log-file=$test_prog.log $test_prog");
}
else
{
    system($test_prog);
}
