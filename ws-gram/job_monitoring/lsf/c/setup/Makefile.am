include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata doxygen

setup_SCRIPTS = setup-seg-lsf.pl find-lsf-logs globus-lsf.conf.in

EXTRA_DIST = setup-seg-lsf.pl.in find-lsf-logs globus-lsf.conf.in

setup-seg-lsf.pl: $(srcdir)/setup-seg-lsf.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

CLEANFILES = setup-seg-lsf.pl

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
