#!/usr/bin/env perl

use strict;
use Test::Harness;
require 5.005;
use vars qw(@tests);

@tests = qw( globus-openssl-error-test.pl
	     );

runtests(@tests);
