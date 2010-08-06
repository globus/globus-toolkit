include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata doxygen

setup_SCRIPTS = \
    condor.in \
    globus-condor-print-config.in \
    find-condor-tools \
    setup-globus-job-manager-condor.pl

EXTRA_DIST = condor.in globus-condor-print-config.in \
        find-condor-tools \
        globus_gram_job_manager_condor.dox

setup-globus-job-manager-condor.pl: $(srcdir)/setup-globus-job-manager-condor.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

CLEANFILES = setup-globus-job-manager-condor.pl

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
