include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

setup_SCRIPTS = \
	findshelltools \
	setup-globus-common \
	setup-globus-common.pl

setup_DATA = \
        globus-sh-tools-vars.sh.in

SUBDIRS = pkgdata

EXTRA_DIST = \
	findshelltools \
	findshelltools.in \
        globus-sh-tools-vars.sh.in \
	setup-globus-common.in \
	setup-globus-common.pl.in

setup-globus-common.pl: setup-globus-common.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

setup-globus-common: setup-globus-common.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

BUILT_SOURCES = setup-globus-common.pl setup-globus-common
CLEANFILES = $(BUILT_SOURCES)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
