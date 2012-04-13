include $(top_srcdir)/globus_automake_pre

EXTRA_DIST= globus-gatekeeper-nolsb.in globus-gatekeeper-lsb.in

gatekeeperinitdir = ${sysconfdir}/init.d
varlockdir = ${localstatedir}/lock
varrundir = ${localstatedir}/run

gatekeeperinit_SCRIPTS = globus-gatekeeper

globus-gatekeeper: globus-gatekeeper$(LSB)
	cp globus-gatekeeper$(LSB) $@

install-data-local:
	mkdir -p $(DESTDIR)$(varlockdir)
	mkdir -p $(DESTDIR)$(varrundir)

CLEANFILES = globus-gatekeeper

include $(top_srcdir)/globus_automake_post
