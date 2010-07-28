include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# Install perl module here:

globustestingperldir = $(GLOBUS_LOCATION)/lib/perl/Globus/Testing

# SUBDIRS is an automake macro which contains 
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	pkgdata 


# Scripts contains all of the scripts in this directory
Scripts= \
	test-toolkit testcred.pem b38b4d8c.0 \
	test-package b38b4d8c.signing_policy \
	global_security_descriptor.xml.in \
	usercert.pem userkey.pem \
        testcred-env.sh testcred-setup.sh

globustestingperl_DATA = \
	Utilities.pm 

test_SCRIPTS = $(Scripts)

# EXTRA_DIST is used to include files in 
# a source distribution that automake fails to detect.
EXTRA_DIST = Utilities.pm.in pkgdata/MyFilelists.pm \
	test-toolkit.in testcred.pem b38b4d8c.0 \
	test-package.in b38b4d8c.signing_policy \
	global_security_descriptor.xml.in \
	usercert.pem userkey.pem \
        testcred-env.sh.in testcred-setup.sh.in
CLEANFILES = test-package test-toolkit testcred-env.sh testcred-setup.sh \
                Utilities.pm

test-package: $(srcdir)/test-package.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
test-toolkit: $(srcdir)/test-toolkit.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
testcred-env.sh: $(srcdir)/testcred-env.sh.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
testcred-setup.sh: $(srcdir)/testcred-setup.sh.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
Utilities.pm: $(srcdir)/Utilities.pm.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top


