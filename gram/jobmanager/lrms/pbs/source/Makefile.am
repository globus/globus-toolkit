include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = seg pkgdata doxygen

## globussysconf = [ DATA ]
globussysconfdir = ${sysconfdir}/globus
globussysconf_DATA = globus-pbs.conf

## gridservices = [ DATA ]
gridservicesdir = ${sysconfdir}/grid-services/available
gridservices_DATA = jobmanager-pbs-poll jobmanager-pbs-seg

## gramperlmodule = [ DATA ]
gramperlmoduledir = ${perlmoduledir}/Globus/GRAM/JobManager
gramperlmodule_DATA = pbs.pm

## validation = [ DATA ]
validationdir = $(datadir)/globus/globus_gram_job_manager
validation_DATA = pbs.rvf

AT=@
jobmanager-pbs-poll: jobmanager-pbs-poll.in
	sed -e "s|$(AT)sbindir$(AT)|$(sbindir)|" \
	    -e "s|$(AT)sysconfdir$(AT)|$(sysconfdir)|" < $< > $@

jobmanager-pbs-seg: jobmanager-pbs-seg.in
	sed -e "s|$(AT)sbindir$(AT)|$(sbindir)|" \
	    -e "s|$(AT)sysconfdir$(AT)|$(sysconfdir)|" < $< > $@

doc_DATA = GLOBUS_LICENSE

EXTRA_DIST = globus-pbs.conf.in pbs.pm $(doc_DATA) $(validation_DATA) \
    jobmanager-pbs-poll.in jobmanager-pbs-seg.in 

CLEANFILES = jobmanager-pbs-poll jobmanager-pbs-seg

if SEG_ENABLED_COND
install-data-local:
	mkdir -p "$(DESTDIR)@globusstatedir@"
	touch "$(DESTDIR)@globusstatedir@/globus-pbs.log"
	chmod 0700 "$(DESTDIR)@globusstatedir@/globus-pbs.log"
endif

# Install link to available file after all other install happens
# native packages can remove this and use globus-gatekeeper-admin to deal
# with the link
if SEG_ENABLED_COND
install-data-hook:
	cd $(DESTDIR)$(gridservicesdir)/..; \
	[ -L "jobmanager-pbs" ] || \
	ln -s available/jobmanager-pbs-seg jobmanager-pbs
else
install-data-hook:
	cd $(DESTDIR)$(gridservicesdir)/..; \
	[ -L "jobmanager-pbs" ] || \
	ln -s available/jobmanager-pbs-poll jobmanager-pbs
endif

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
