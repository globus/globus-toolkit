include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# pod documentation dirs
perldocdir=$(datadir)/doc/perl

SUBDIRS = pkgdata doxygen

setup_SCRIPTS = \
    setup-globus-gram-job-manager.pl

EXTRA_DIST = \
    setup-globus-gram-job-manager.pl.in \
    globus_gram_job_manager_program_setup.dox

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
