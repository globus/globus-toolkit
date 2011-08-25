include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = seg pkgdata doxygen

## globussysconf = [ DATA ]
globussysconfdir = ${sysconfdir}/globus
globussysconf_DATA = globus-sge.conf

## gridservices = [ DATA ]
gridservicesdir = ${sysconfdir}/grid-services/available
gridservices_DATA = jobmanager-sge-poll jobmanager-sge-seg

## gramperlmodule = [ DATA ]
gramperlmoduledir = ${perlmoduledir}/Globus/GRAM/JobManager
gramperlmodule_DATA = sge.pm

doc_DATA = AUTHORS CREDITS LICENSE LICENSE.GTPL LICENSE.LGPL README.txt

EXTRA_DIST = globus-sge.conf.in sge.pm $(doc_DATA)

# Install link to available file after all other install happens
# native packages can remove this and use globus-gatekeeper-admin to deal
# with the link
if SEG_ENABLED_COND
install-data-hook:
	cd $(DESTDIR)$(gridservicesdir)/..; \
	[ -L "jobmanager-sge" ] || \
	ln -s available/jobmanager-sge-seg jobmanager-sge
else
install-data-hook:
	cd $(DESTDIR)$(gridservicesdir)/..; \
	[ -L "jobmanager-sge" ] || \
	ln -s available/jobmanager-sge-poll jobmanager-sge
endif

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
