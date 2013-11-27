gatekeeperinit_SCRIPTS = globus-gatekeeper

gatekeeperinitdir = ${sysconfdir}/init.d
varlockdir = ${localstatedir}/lock
varrundir = ${localstatedir}/run

globus-gatekeeper: globus-gatekeeper$(LSB)
	cp globus-gatekeeper$(LSB) $@

install-data-local:
	mkdir -p $(DESTDIR)$(varlockdir)
	mkdir -p $(DESTDIR)$(varrundir)

EXTRA_DIST = globus-gatekeeper-nolsb.in globus-gatekeeper-lsb.in
CLEANFILES = globus-gatekeeper
