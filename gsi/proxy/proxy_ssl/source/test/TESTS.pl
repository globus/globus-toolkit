#! /usr/bin/perl

BEGIN
{
    $ENV{PATH} = dirname($0) . ":.:" . $ENV{PATH};
}
use warnings;
use strict;
use Test::Harness;

use vars qw(@tests);

@tests = qw(test_pci.pl);

runtests(@tests);
