include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = starter seg pkgdata doxygen

## globussysconf = [ DATA ]
globussysconfdir = ${sysconfdir}/globus
globussysconf_DATA = globus-fork.conf

## gridservices = [ DATA ]
gridservicesdir = ${sysconfdir}/grid-services/available
gridservices_DATA = jobmanager-fork-poll jobmanager-fork-seg

## gramperlmodule = [ DATA ]
gramperlmoduledir = ${perlmoduledir}/Globus/GRAM/JobManager
gramperlmodule_DATA = fork.pm

doc_DATA = GLOBUS_LICENSE

AT=@

jobmanager-fork-poll: jobmanager-fork-poll.in
	sed -e "s|$(AT)sbindir$(AT)|$(sbindir)|" \
            -e "s|$(AT)sysconfdir$(AT)|$(sysconfdir)|" < $< > $@

jobmanager-fork-seg: jobmanager-fork-seg.in
	sed -e "s|$(AT)sbindir$(AT)|$(sbindir)|" \
            -e "s|$(AT)sysconfdir$(AT)|$(sysconfdir)|" < $< > $@

EXTRA_DIST = fork.pm jobmanager-fork-poll.in jobmanager-fork-seg.in $(doc_DATA)

CLEANFILES = jobmanager-fork-poll jobmanager-fork-seg

if SEG_ENABLED_COND
install-data-local:
	mkdir -p "$(DESTDIR)@globusstatedir@"
	touch "$(DESTDIR)@globusstatedir@/globus-fork.log"
	chmod 0777 "$(DESTDIR)@globusstatedir@/globus-fork.log"
endif

# Install link to available file after all other install happens
# native packages can remove this and use globus-gatekeeper-admin to deal
# with the link
if SEG_ENABLED_COND
install-data-hook:
	cd $(DESTDIR)$(gridservicesdir)/..; \
	[ -L "jobmanager-fork" ] || \
	ln -s available/jobmanager-fork-seg jobmanager-fork
else
install-data-hook:
	cd $(DESTDIR)$(gridservicesdir)/..; \
	[ -L "jobmanager-fork" ] || \
	ln -s available/jobmanager-fork-poll jobmanager-fork
endif


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
