include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata doxygen

setup_SCRIPTS = \
    setup-globus-gaa-authz-callout \
    setup-globus-gaa-authz-callout-message \
    setup-globus-gaa-authz-callout-message.pl \
    setup-globus-gaa-authz-callout.pl \
    gsi-gaa.conf.tmpl

EXTRA_DIST = \
    setup-globus-gaa-authz-callout.in \
    setup-globus-gaa-authz-callout-message.in \
    setup-globus-gaa-authz-callout-message.pl \
    setup-globus-gaa-authz-callout.pl.in \
    globus_gaa_authz_callout.dox

CLEANFILES = \
    setup-globus-gaa-authz-callout \
    setup-globus-gaa-authz-callout-message \
    setup-globus-gaa-authz-callout.pl

setup-globus-gaa-authz-callout.pl: $(srcdir)/setup-globus-gaa-authz-callout.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

setup-globus-gaa-authz-callout: $(srcdir)/setup-globus-gaa-authz-callout.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

setup-globus-gaa-authz-callout-message: $(srcdir)/setup-globus-gaa-authz-callout-message.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
