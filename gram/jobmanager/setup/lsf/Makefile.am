include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata doxygen

setup_SCRIPTS = \
    lsf.in \
    find-lsf-tools \
    setup-globus-job-manager-lsf.pl

EXTRA_DIST = lsf.in find-lsf-tools globus_gram_job_manager_lsf.dox setup-globus-job-manager-lsf.pl.in

setup-globus-job-manager-lsf.pl: $(srcdir)/setup-globus-job-manager-lsf.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

CLEANFILES = setup-globus-job-manager-lsf.pl

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
