include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# pod documentation dirs
perldocdir=$(GLOBUS_LOCATION)/share/doc/perl
mandir=$(GLOBUS_LOCATION)/man/man1

SUBDIRS = pkgdata doxygen

perldoc_DATA = globus-job-manager-service.html
man_MANS = globus-job-manager-service.1

setup_SCRIPTS = \
    globus-job-manager-script.in \
    setup-globus-gram-job-manager \
    setup-globus-gram-job-manager.pl \
    globus-job-manager-service.in \
    globus-job-manager-mds-provider.in


EXTRA_DIST = \
    globus-job-manager-script.in \
    setup-globus-gram-job-manager \
    setup-globus-gram-job-manager.pl \
    globus-job-manager-service.in \
    globus-job-manager-mds-provider.in \
    $(perldoc_DATA) $(man_MANS) \
    globus_gram_job_manager_program_setup.dox

SUFFIXES = .html .1 .in

.in.html:
	pod2html --noindex $*.in | \
	     sed -e  's,</HEAD>,<LINK REL="stylesheet" HREF="../../doxygen/globus.css"></HEAD>,' > $*.html

.in.1:
	pod2man --section=1 --center "Globus Toolkit(tm)" $*.in > $*.1

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
