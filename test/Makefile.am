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
	test-toolkit testcred.pem dc31a685.0 \
	dc31a685.signing_policy \
	global_security_descriptor.xml.in \
        testcred-env.sh testcred-setup.sh

globustestingperl_DATA = \
	Utilities.pm 

test_SCRIPTS = $(Scripts)

# EXTRA_DIST is used to include files in 
# a source distribution that automake fails to detect.
EXTRA_DIST = $(Scripts) Utilities.pm pkgdata/MyFilelists.pm

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top


