include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata 

## globussysconf = [ DATA ]
globussysconfdir = ${sysconfdir}/globus
globussysconf_DATA = globus-condor.conf

## gridservices = [ DATA ]
gridservicesdir = ${sysconfdir}/grid-services/available
gridservices_DATA = jobmanager-condor

AT=@

jobmanager-condor: jobmanager-condor.in
	sed -e "s|$(AT)sbindir$(AT)|$(sbindir)|" \
	    -e "s|$(AT)sysconfdir$(AT)|$(sysconfdir)|" < $< > $@

## validation = [ DATA ]
validationdir = $(datadir)/globus/globus_gram_job_manager
validation_DATA = condor.rvf

## gramperlmodule = [ DATA ]
gramperlmoduledir = ${perlmoduledir}/Globus/GRAM/JobManager
gramperlmodule_DATA = condor.pm

doc_DATA = GLOBUS_LICENSE

# Install link to available file after all other install happens
# native packages can remove this and use globus-gatekeeper-admin to deal
# with the link
install-data-hook:
	cd $(DESTDIR)$(gridservicesdir)/..; \
	[ -L "$(gridservices_DATA)" ] || ln -s available/$(gridservices_DATA) .

EXTRA_DIST = condor.pm condor.rvf globus-condor.conf.in jobmanager-condor.in \
	GLOBUS_LICENSE

CLEANFILES = jobmanager-condor

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
