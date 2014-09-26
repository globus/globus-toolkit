globussysconfdir = ${sysconfdir}/globus
gridservicesdir = ${sysconfdir}/grid-services/available
gramperlmoduledir = ${perlmoduledir}/Globus/GRAM/JobManager
validationdir = $(datadir)/globus/globus_gram_job_manager

globussysconf_DATA = globus-slurm.conf
gridservices_DATA = jobmanager-slurm-poll
gramperlmodule_DATA = slurm.pm
validation_DATA = slurm.rvf
doc_DATA = LICENSE GLOBUS_LICENSE LICENSE.BSD

AT=@
jobmanager-slurm-poll: jobmanager-slurm.in
	sed -e "s|$(AT)sbindir$(AT)|$(sbindir)|" \
	    -e "s|$(AT)sysconfdir$(AT)|$(sysconfdir)|" < $< > $@

EXTRA_DIST = \
        dirt.sh \
        slurm.pm \
        $(doc_DATA) \
        jobmanager-slurm.in

CLEANFILES = jobmanager-slurm-poll

DISTCLEANFILES = mpi_type.rvf

install-data-hook:
	cd $(DESTDIR)$(gridservicesdir)/..; \
	[ -L "jobmanager-slurm" ] || \
	ln -s available/jobmanager-slurm-poll jobmanager-slurm

distuninstallcheck:
	@:
