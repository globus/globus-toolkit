include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

bin_SCRIPTS = grid-ca-sign

SUBDIRS = pkgdata

EXTRA_DIST = grid-ca-sign.in

grid-ca-sign: grid-ca-sign.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

CLEANFILES = grid-ca-sign
BUILT_SOURCES = grid-ca-sign

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
