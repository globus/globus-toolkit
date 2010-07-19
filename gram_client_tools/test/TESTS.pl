#!/usr/bin/env perl

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

my $exitCode = 0;

my @tests = qw(
               globus-gram-client-tools-check-for-commands.pl
               globus-gram-client-tools-local-test.pl
               globus-gram-client-tools-remote-test.pl
               );

if(0 != system("grid-proxy-info -exists -hours 2 2>/dev/null") / 256)
{
    $ENV{X509_CERT_DIR} = cwd();
    $ENV{X509_USER_PROXY} = "testcred.pem";
    system('chmod go-rw testcred.pem'); 
}

foreach (@tests)
{
    $exitCode += system("./$_");
}


exit (0 != $exitCode);
