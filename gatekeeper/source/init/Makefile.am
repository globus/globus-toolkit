include $(top_srcdir)/globus_automake_pre

EXTRA_DIST= globus-gatekeeper.in globus-gatekeeper-lsb.in

gatekeeperinitdir = ${sysconfdir}/init.d
gatekeeperinit_SCRIPTS = globus-gatekeeper

globus-gatekeeper: $(srcdir)/$(INIT_SCRIPT_SOURCE)
	$(REWRITE_SCRIPT_PREFIXES) < $< | \
        sed -e 's|$(AT)GATEKEEPER_CONFIGDIR$(AT)|@GATEKEEPER_CONFIGDIR@|g' \
        -e 's|$(AT)GATEKEEPER_CONFIGFILE$(AT)|@GATEKEEPER_CONFIGFILE@|g' \
        > $@

CLEANFILES = globus-gatekeeper

include $(top_srcdir)/globus_automake_post
