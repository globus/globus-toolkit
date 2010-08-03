include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata schemas

setup_SCRIPTS = setup-globus-gram-auditing

EXTRA_DIST = setup-globus-gram-auditing.in
CLEANFILES = setup-globus-gram-auditing

setup-globus-gram-auditing: setup-globus-gram-auditing.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
