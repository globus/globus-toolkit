include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# pod documentation dirs
perldocdir=$(GLOBUS_LOCATION)/share/doc/perl
mandir=$(GLOBUS_LOCATION)/man/man1

SUBDIRS = pkgdata doxygen

setup_SCRIPTS = \
    setup-globus-gram-job-manager \
    setup-globus-gram-job-manager.pl

EXTRA_DIST = \
    setup-globus-gram-job-manager.in \
    setup-globus-gram-job-manager.pl.in \
    globus_gram_job_manager_program_setup.dox

setup-globus-gram-job-manager: $(srcdir)/setup-globus-gram-job-manager.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

setup-globus-gram-job-manager.pl: $(srcdir)/setup-globus-gram-job-manager.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

CLEANFILES = setup-globus-gram-job-manager setup-globus-gram-job-manager.pl 

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
