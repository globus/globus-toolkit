include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# SUBDIRS is an automake macro which contains 
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	pkgdata 


# Scripts contains all of the scripts in this directory
Scripts= \
	TESTS.pl \
	Utilities.pm \
    globus_test_check_for_commands.pl \
    globus_test_check_proxy.pl \
    globus_test_gram_local.pl \
    globus_test_gram_remote.pl \
    globus_test_gridftp_local.pl \
    globus_test_gridftp_remote.pl \
    globus_test_mds_local.pl \
    globus_test_mds_remote.pl \
    globus_test_setup_environment.pl

test_SCRIPTS = $(Scripts)

# EXTRA_DIST is used to include files in 
# a source distribution that automake fails to detect.
EXTRA_DIST = $(Scripts)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top


