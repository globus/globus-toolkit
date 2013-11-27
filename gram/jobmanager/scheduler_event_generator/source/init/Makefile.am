seginitdir = ${sysconfdir}/init.d
seginit_SCRIPTS = globus-scheduler-event-generator

varlockdir = ${localstatedir}/lock
varrundir = ${localstatedir}/run

globus-scheduler-event-generator: globus-scheduler-event-generator$(LSB)
	cp globus-scheduler-event-generator$(LSB) $@

install-data-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/globus/scheduler-event-generator/available
	mkdir -p $(DESTDIR)$(varlockdir)
	mkdir -p $(DESTDIR)$(varrundir)

CLEANFILES = globus-scheduler-event-generator
