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

my @tests = qw( 
        globus_test_check_for_commands.pl
        globus_test_check_proxy.pl
        globus_test_gram_local.pl
        globus_test_gram_remote.pl
        globus_test_gridftp_local.pl
        globus_test_gridftp_remote.pl
);

#       globus_test_setup_environment.pl
#       globus_test_mds_local.pl
#       globus_test_mds_remote.pl

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
