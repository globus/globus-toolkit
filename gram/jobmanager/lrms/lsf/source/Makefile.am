include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = seg pkgdata doxygen

## globussysconf = [ DATA ]
globussysconfdir = ${sysconfdir}/globus
globussysconf_DATA = globus-lsf.conf

## gridservices = [ DATA ]
gridservicesdir = ${sysconfdir}/grid-services/available
gridservices_DATA = jobmanager-lsf-poll jobmanager-lsf-seg

## gramperlmodule = [ DATA ]
gramperlmoduledir = ${perlmoduledir}/Globus/GRAM/JobManager
gramperlmodule_DATA = lsf.pm

## validation = [ DATA ]
validationdir = $(datadir)/globus/globus_gram_job_manager
validation_DATA = lsf.rvf

AT=@
jobmanager-lsf-poll: jobmanager-lsf-poll.in
	sed -e "s|$(AT)sbindir$(AT)|$(sbindir)|" \
	    -e "s|$(AT)sysconfdir$(AT)|$(sysconfdir)|" < $< > $@

jobmanager-lsf-seg: jobmanager-lsf-seg.in
	sed -e "s|$(AT)sbindir$(AT)|$(sbindir)|" \
	    -e "s|$(AT)sysconfdir$(AT)|$(sysconfdir)|" < $< > $@

doc_DATA = GLOBUS_LICENSE

EXTRA_DIST = globus-lsf.conf.in lsf.pm $(doc_DATA) $(validation_DATA) \
    jobmanager-lsf-poll.in jobmanager-lsf-seg.in 

CLEANFILES = jobmanager-lsf-poll jobmanager-lsf-seg

if SEG_ENABLED_COND
install-data-local:
	mkdir -p "$(DESTDIR)@globusstatedir@"
	touch "$(DESTDIR)@globusstatedir@/globus-lsf.log"
	chmod 0700 "$(DESTDIR)@globusstatedir@/globus-lsf.log"
endif

# Install link to available file after all other install happens
# native packages can remove this and use globus-gatekeeper-admin to deal
# with the link
if SEG_ENABLED_COND
install-data-hook:
	cd $(DESTDIR)$(gridservicesdir)/..; \
	[ -L "jobmanager-lsf" ] || \
	ln -s available/jobmanager-lsf-seg jobmanager-lsf
else
install-data-hook:
	cd $(DESTDIR)$(gridservicesdir)/..; \
	[ -L "jobmanager-lsf" ] || \
	ln -s available/jobmanager-lsf-poll jobmanager-lsf
endif

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
