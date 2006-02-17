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

my $test_prog = './run-common-tests.pl';

# Accomodate running tests on Windows platform - remove leading './'
if ("$^O" =~ /win32/i)
{
   $test_prog =~ s/(.\/)//;
}

my $res = system("$test_prog");
exit ( $res != 0 );

