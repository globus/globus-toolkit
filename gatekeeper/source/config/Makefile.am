include $(top_srcdir)/globus_automake_pre

EXTRA_DIST= globus-gatekeeper.in

gatekeeperconfdir = $(GATEKEEPER_CONFIGDIR)
gatekeeperconf_DATA = $(GATEKEEPER_CONFIGFILE)

$(GATEKEEPER_CONFIGFILE): $(srcdir)/globus-gatekeeper.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

CLEANFILES = $(GATEKEEPER_CONFIGFILE)

include $(top_srcdir)/globus_automake_post
