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


# -----------------------------------------------------------------------
# TESTS.pl - This script calls all the other tests in the current
# directory only. 
#
# In each directory behind the Globus CVS test module, there will be a
# TESTS.pl file for that directory which will call all the scripts in
# that directory.  The 'test-toolkit' script in side_tools/ will
# recursively search the test/ directory and run the TESTS.pl script in 
# each directory.
#
# You should only modify the @tests array below.  That's it.
#
# -----------------------------------------------------------------------


use strict;
use Cwd;

my @tests = qw(
               globus-gass-copy-check-for-commands.pl
               globus-gass-copy-local-test.pl
               globus-gass-copy-remote-test.pl
               );

if(0 != system("grid-proxy-info -exists -hours 2 2>/dev/null") / 256)
{
    $ENV{X509_CERT_DIR} = cwd();
    $ENV{X509_USER_PROXY} = "testcred.pem";
    system('chmod go-rw testcred.pem'); 
}

foreach (@tests)
{
    system("./$_");
}
