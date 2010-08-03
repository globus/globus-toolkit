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
EXTRA_DIST=globus-user-env.sh.in globus-user-env.csh.in

globus-user-env.sh: globus-user-env.sh.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-user-env.csh: globus-user-env.csh.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

CLEANFILES = globus-user-env.sh globus-user-env.csh
BUILT_SOURCES = globus-user-env.sh globus-user-env.csh

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

