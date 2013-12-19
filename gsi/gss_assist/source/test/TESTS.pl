#! /usr/bin/perl

use strict;
use warnings;
use Test::Harness;
require 5.005;
use vars qw(@tests);

@tests = qw(gss-assist-impexp-test.pl
            gss-assist-auth-test.pl
            gss-assist-gridmap-test.pl
            gridmap-test.pl
            gridmap-tools-test.pl
            );

runtests(@tests);
