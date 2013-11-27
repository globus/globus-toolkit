AUTOMAKE_OPTIONS = foreign

globussysconfdir = ${sysconfdir}/globus
gridservicesdir = ${sysconfdir}/grid-services/available
validationdir = $(datadir)/globus/globus_gram_job_manager
gramperlmoduledir = ${perlmoduledir}/Globus/GRAM/JobManager

globussysconf_DATA = globus-condor.conf
gridservices_DATA = jobmanager-condor
validation_DATA = condor.rvf
gramperlmodule_DATA = condor.pm
doc_DATA = GLOBUS_LICENSE

AT=@

jobmanager-condor: jobmanager-condor.in
	sed -e "s|$(AT)sbindir$(AT)|$(sbindir)|" \
	    -e "s|$(AT)sysconfdir$(AT)|$(sysconfdir)|" < $< > $@


# Install link to available file after all other install happens
# native packages can remove this and use globus-gatekeeper-admin to deal
# with the link
install-data-hook:
	cd $(DESTDIR)$(gridservicesdir)/..; \
	[ -L "$(gridservices_DATA)" ] || ln -s available/$(gridservices_DATA) .

EXTRA_DIST = \
        dirt.sh \
        condor.pm \
        condor.rvf \
        globus-condor.conf.in \
        jobmanager-condor.in \
	GLOBUS_LICENSE

CLEANFILES = jobmanager-condor
