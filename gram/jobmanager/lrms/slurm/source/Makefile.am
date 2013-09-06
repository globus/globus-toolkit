include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata 

## globussysconf = [ DATA ]
globussysconfdir = ${sysconfdir}/globus
globussysconf_DATA = globus-slurm.conf

## gridservices = [ DATA ]
gridservicesdir = ${sysconfdir}/grid-services/available
gridservices_DATA = jobmanager-slurm-poll

## gramperlmodule = [ DATA ]
gramperlmoduledir = ${perlmoduledir}/Globus/GRAM/JobManager
gramperlmodule_DATA = slurm.pm

## validation = [ DATA ]
validationdir = $(datadir)/globus/globus_gram_job_manager
validation_DATA = slurm.rvf

doc_DATA = LICENSE GLOBUS_LICENSE LICENSE.BSD

AT=@
jobmanager-slurm-poll: jobmanager-slurm.in
	sed -e "s|$(AT)sbindir$(AT)|$(sbindir)|" \
	    -e "s|$(AT)sysconfdir$(AT)|$(sysconfdir)|" < $< > $@

EXTRA_DIST = globus-slurm.conf.in slurm.pm $(doc_DATA) $(validation_DATA) \
        jobmanager-slurm.in

CLEANFILES = jobmanager-slurm-poll

install-data-hook:
	cd $(DESTDIR)$(gridservicesdir)/..; \
	[ -L "jobmanager-slurm" ] || \
	ln -s available/jobmanager-slurm-poll jobmanager-slurm

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
