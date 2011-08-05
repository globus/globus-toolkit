include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = starter seg pkgdata doxygen

## globussysconf = [ DATA ]
globussysconfdir = ${sysconfdir}/globus
globussysconf_DATA = globus-fork.conf

## gridservices = [ DATA ]
gridservicesdir = ${sysconfdir}/grid-services/available
gridservices_DATA = jobmanager-fork

## gramperlmodule = [ DATA ]
gramperlmoduledir = ${perlmoduledir}/Globus/GRAM/JobManager
gramperlmodule_DATA = fork.pm

doc_DATA = GLOBUS_LICENSE

EXTRA_DIST = jobmanager-fork.in globus-fork.conf.in fork.pm $(doc_DATA)

if SEG_ENABLED_COND
install-data-local:
	mkdir -p "$(DESTDIR)@globusstatedir@"
	touch "$(DESTDIR)@globusstatedir@/globus-fork.log"
	chmod 0777 "$(DESTDIR)@globusstatedir@/globus-fork.log"
endif

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
