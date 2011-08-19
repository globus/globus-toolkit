include $(top_srcdir)/globus_automake_pre

## seginit = [ DATA ]
seginitdir = ${sysconfdir}/init.d
seginit_SCRIPTS = globus-scheduler-event-generator

globus-scheduler-event-generator: globus-scheduler-event-generator$(LSB)
	cp globus-scheduler-event-generator$(LSB) $@

install-data-hook:
	mkdir -p $(sysconfdir)/globus/scheduler-event-generator/available

CLEANFILES = globus-scheduler-event-generator

include $(top_srcdir)/globus_automake_post
