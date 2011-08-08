include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata 

## globussysconf = [ DATA ]
globussysconfdir = ${sysconfdir}/globus
globussysconf_DATA = globus-condor.conf

## gridservices = [ DATA ]
gridservicesdir = ${sysconfdir}/grid-services/available
gridservices_DATA = jobmanager-condor

## validation = [ DATA ]
validationdir = $(datadir)/globus/globus_gram_job_manager
validation_DATA = condor.rvf

## gramperlmodule = [ DATA ]
gramperlmoduledir = ${perlmoduledir}/Globus/GRAM/JobManager
gramperlmodule_DATA = condor.pm

doc_DATA = GLOBUS_LICENSE

install-data-local:
	cd $(DESTDIR)$(gridservicesdir); ln -s available/jobmanager-condor .

EXTRA_DIST = condor.pm condor.rvf globus-condor.conf.in jobmanager-condor.in \
	GLOBUS_LICENSE

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
