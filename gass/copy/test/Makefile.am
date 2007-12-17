include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# SUBDIRS is an automake macro which contains 
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	pkgdata 


# Scripts contains all of the scripts in this directory
Scripts= \
	TESTS.pl \
    guc-stack.pl \
    guc-simple.pl \
    guc-pp-cc.pl \
    guc-cc.pl \
	globus-gass-copy-check-for-commands.pl \
	globus-gass-copy-local-test.pl \
	globus-gass-copy-remote-test.pl

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


