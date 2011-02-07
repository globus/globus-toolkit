include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# SUBDIRS is an automake macro which contains 
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	pkgdata 


# Scripts contains all of the scripts in this directory
Scripts= \
	TESTS.pl \
	globus-gass-copy-local-test.pl \
	globus-gass-copy-remote-test.pl \
        guc-cc.pl \
        guc-fw.pl \
        guc-pp-cc.pl \
        guc-simple.pl \
        guc-stack.pl
ScriptSources =  \
	globus-gass-copy-local-test.pl.in \
	globus-gass-copy-remote-test.pl.in \
        guc-cc.pl.in \
        guc-fw.pl.in \
        guc-pp-cc.pl.in \
        guc-simple.pl.in \
        guc-stack.pl.in
Data = \
	dc31a685.0 \
	dc31a685.signing_policy \
	testcred.pem


test_SCRIPTS = $(Scripts)
test_DATA=$(Data)

CLEANFILES = globus-test-perl-initializer

# EXTRA_DIST is used to include files in 
# a source distribution that automake fails to detect.
EXTRA_DIST = TESTS.pl $(ScriptSources) $(Data)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top


