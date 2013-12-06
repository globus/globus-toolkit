#! /usr/bin/perl

@GLOBUS_PERL_INITIALIZER@

BEGIN
{
    $ENV{PATH} = ".:" . $ENV{PATH};
}
require 5.005;

use warnings;
use strict;
use Test::Harness;

use vars qw(@tests);

@tests = qw(test_pci.pl);

runtests(@tests);
