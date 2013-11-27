include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# SUBDIRS is an automake macro which contains 
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	pkgdata 


# Scripts contains all of the scripts in this directory
Scripts = \
	TESTS.pl \
	globus-gram-client-tools-local-test.pl \
	globus-gram-client-tools-remote-test.pl

ScriptsIn = \
	TESTS.pl.in \
	globus-gram-client-tools-local-test.pl.in \
	globus-gram-client-tools-remote-test.pl.in

Data = \
	dc31a685.0 \
	dc31a685.signing_policy \
	testcred.pem


test_SCRIPTS = $(Scripts)

test_DATA=$(Data)

# EXTRA_DIST is used to include files in 
# a source distribution that automake fails to detect.
EXTRA_DIST = $(ScriptsIn) $(Data)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
