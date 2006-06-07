include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata doxygen

setup_SCRIPTS = \
    condor.in \
    globus-condor-print-config.in \
    find-condor-tools \
    setup-globus-job-manager-condor.pl

EXTRA_DIST = $(setup_SCRIPTS) globus_gram_job_manager_condor.dox

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
