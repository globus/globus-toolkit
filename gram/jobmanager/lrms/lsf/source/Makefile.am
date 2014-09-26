ACLOCAL_AMFLAGS=-I m4
SUBDIRS = seg

globussysconfdir = ${sysconfdir}/globus
gridservicesdir = ${sysconfdir}/grid-services/available
gramperlmoduledir = ${perlmoduledir}/Globus/GRAM/JobManager
validationdir = $(datadir)/globus/globus_gram_job_manager

globussysconf_DATA = globus-lsf.conf
gridservices_DATA = jobmanager-lsf-poll jobmanager-lsf-seg
gramperlmodule_DATA = lsf.pm
validation_DATA = lsf.rvf
doc_DATA = GLOBUS_LICENSE

AT=@
jobmanager-lsf-poll: $(srcdir)/jobmanager-lsf-poll.in
	sed -e "s|$(AT)sbindir$(AT)|$(sbindir)|" \
	    -e "s|$(AT)sysconfdir$(AT)|$(sysconfdir)|" < $< > $@

jobmanager-lsf-seg: $(srcdir)/jobmanager-lsf-seg.in
	sed -e "s|$(AT)sbindir$(AT)|$(sbindir)|" \
	    -e "s|$(AT)sysconfdir$(AT)|$(sysconfdir)|" < $< > $@

EXTRA_DIST = \
        dirt.sh \
        lsf.pm \
        $(doc_DATA) \
        $(validation_DATA) \
        jobmanager-lsf-poll.in \
        jobmanager-lsf-seg.in 

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

distuninstallcheck:
	@:
