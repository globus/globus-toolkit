include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata doxygen

setup_SCRIPTS = setup-seg-pbs.pl 

EXTRA_DIST = setup-seg-pbs.pl.in
CLEANFILES = setup-seg-pbs.pl

setup-seg-pbs.pl: $(srcdir)/setup-seg-pbs.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
