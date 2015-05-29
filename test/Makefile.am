include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# Install perl module here:

globustestingperldir = $(perlmoduledir)/Globus/Testing

# SUBDIRS is an automake macro which contains 
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	pkgdata 


# Scripts contains all of the scripts in this directory
Scripts= \
	test-toolkit testcred.pem \
	test-package \
	global_security_descriptor.xml.in \
        3b4121e7.0 3b4121e7.signing_policy \
        55184f03.0 55184f03.signing_policy \
	usercert.pem userkey.pem \
        testcred-env.sh testcred-setup.sh

globustestingperl_DATA = \
	Utilities.pm 

test_SCRIPTS = $(Scripts)

# EXTRA_DIST is used to include files in 
# a source distribution that automake fails to detect.
EXTRA_DIST = Utilities.pm.in \
	test-toolkit.in testcred.pem \
	test-package.in \
        3b4121e7.0 3b4121e7.signing_policy \
        55184f03.0 55184f03.signing_policy \
	global_security_descriptor.xml.in \
	usercert.pem userkey.pem \
        testcred-env.sh.in testcred-setup.sh.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top


