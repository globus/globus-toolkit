include $(top_srcdir)/globus_automake_pre

EXTRA_DIST= globus-gatekeeper-nolsb.in globus-gatekeeper-lsb.in

gatekeeperinitdir = ${sysconfdir}/init.d
varlockdir = ${localstatedir}/lock
varrundir = ${localstatedir}/run

gatekeeperinit_SCRIPTS = globus-gatekeeper

globus-gatekeeper: globus-gatekeeper$(LSB)
	cp globus-gatekeeper$(LSB) $@

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(varlockdir)
	$(MKDIR_P) $(DESTDIR)$(varrundir)

CLEANFILES = globus-gatekeeper

include $(top_srcdir)/globus_automake_post
