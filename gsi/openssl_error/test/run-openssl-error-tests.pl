#!/usr/bin/perl

use strict;
use Test::Harness;
require 5.005;
use vars qw(@tests);

@tests = qw( globus_openssl_error_test.pl
	     );

runtests(@tests);
