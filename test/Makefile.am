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
	test-toolkit \
	globus-test-check-for-commands.pl \
	globus-test-check-proxy.pl \
	globus-test-gram-local.pl \
	globus-test-gram-remote.pl \
	globus-test-gridftp-local.pl \
	globus-test-gridftp-remote.pl \
	globus-test-mds-local.pl \
	globus-test-mds-remote.pl

Data = \
	dc31a685.0 \
	dc31a685.signing_policy \
	testcred.pem


test_SCRIPTS = $(Scripts)

test_DATA=$(Data)

# EXTRA_DIST is used to include files in 
# a source distribution that automake fails to detect.
EXTRA_DIST = $(Scripts) $(Data)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top


