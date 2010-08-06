include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

Scripts = setup-openssl
setup_SCRIPTS = $(Scripts)

SUBDIRS = pkgdata

EXTRA_DIST = dirt.sh setup-openssl.in

CLEANFILES = setup-openssl

setup-openssl: $(srcdir)/setup-openssl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
