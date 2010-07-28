include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# SUBDIRS is an automake macro which contains 
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	pkgdata 


# Scripts contains all of the scripts in this directory
Scripts= \
	TESTS.pl \
	globus-gass-copy-check-for-commands.pl \
	globus-gass-copy-local-test.pl \
	globus-gass-copy-remote-test.pl \
        guc-cc.pl \
        guc-fw.pl \
        guc-pp-cc.pl \
        guc-simple.pl \
        guc-stack.pl
ScriptSources =  \
	globus-gass-copy-check-for-commands.pl.in \
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

globus-gass-copy-check-for-commands.pl: globus-gass-copy-check-for-commands.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-gass-copy-local-test.pl: globus-gass-copy-local-test.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-gass-copy-local-test.pl: globus-gass-copy-local-test.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-gass-copy-remote-test.pl: globus-gass-copy-remote-test.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
guc-cc.pl: guc-cc.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
guc-fw.pl: guc-fw.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
guc-pp-cc.pl.in: guc-pp-cc.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
guc-simple.pl: guc-simple.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
guc-stack.pl: guc-stack.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

# EXTRA_DIST is used to include files in 
# a source distribution that automake fails to detect.
EXTRA_DIST = TESTS.pl $(ScriptSources) $(Data)
CLEANFILES = \
        globus-gass-copy-check-for-commands.pl \
	globus-gass-copy-local-test.pl \
	globus-gass-copy-remote-test.pl \
        guc-cc.pl \
        guc-fw.pl \
        guc-pp-cc.pl \
        guc-simple.pl \
        guc-stack.pl

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top


