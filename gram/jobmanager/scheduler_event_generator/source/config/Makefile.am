segconfdir = @SEG_CONFIGDIR@
segconf_DATA = @SEG_CONFIGFILE@

$(SEG_CONFIGFILE): globus-scheduler-event-generator.in
	../config.status --file $(SEG_CONFIGFILE):$(srcdir)/globus-scheduler-event-generator.in

CLEANFILES = $(SEG_CONFIGFILE) config.log

EXTRA_DIST = globus-scheduler-event-generator.in
