include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata doxygen

setup_SCRIPTS = \
    fork.in \
    find-fork-tools \
    setup-globus-job-manager-fork.pl

EXTRA_DIST = fork.in find-fork-tools globus_gram_job_manager_fork.dox

setup-globus-job-manager-fork.pl: $(srcdir)/setup-globus-job-manager-fork.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

CLEANFILES = setup-globus-job-manager-fork.pl

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
