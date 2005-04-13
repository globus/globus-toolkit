include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top


# SUBDIRS is an automake macro which contains 
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	doxygen \
	pkgdata 


test_SCRIPTS = TESTS.pl test-pbs-seg.pl
test_DATA = test-data.txt

EXTRA_DIST= $(test_DATA) $(test_SCRIPTS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
