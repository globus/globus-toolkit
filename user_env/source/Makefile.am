include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# SUBDIRS is an automake macro which contains 
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	pkgdata \
	doxygen

Scripts= \
	globus-user-env.sh \
	globus-user-env.csh

sysconf_DATA=$(Scripts)
EXTRA_DIST=$(Scripts)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

