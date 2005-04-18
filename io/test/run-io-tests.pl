#!/usr/bin/env perl

#
# Portions of this file Copyright 1999-2005 University of Chicago
# Portions of this file Copyright 1999-2005 The University of Southern California.
#
# This file or a portion of this file is licensed under the
# terms of the Globus Toolkit Public License, found at
# http://www.globus.org/toolkit/download/license.html.
# If you redistribute this file, with or without
# modifications, you must include this notice in the file.
#


use strict;
use Test::Harness;
require 5.005;
use vars qw(@tests);

my $globus_location = $ENV{GLOBUS_LOCATION};

system('chmod go-rw testcred.pem');

@tests = qw( globus-io-file-test.pl
             globus-io-authorization-test.pl
	     globus-io-tcp-test.pl
	     );

push(@INC, $ENV{GLOBUS_LOCATION} . "/lib/perl");

runtests(@tests);
