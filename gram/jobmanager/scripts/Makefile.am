include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata

libexec_SCRIPTS = \
	globus-job-manager-service      \
	globus-job-manager-script.pl

# Extra directories we install files into
globusperldir=$(GLOBUS_LOCATION)/lib/perl/Globus/GRAM
perldocdir=$(GLOBUS_LOCATION)/share/doc/perl/Globus/GRAM

# Where targets are installed
globusperl_DATA = \
    JobDescription.pm \
    JobManager.pm \
    StdioMerger.pm
perldoc_DATA = JobManager.html JobDescription.html

# Files which we want to put in the source package
EXTRA_DIST = globus-job-manager-service.in globus-job-manager-script.pl.in \
            JobDescription.pm.in \
            JobManager.pm StdioMerger.pm $(perldoc_DATA) $(noinst_DATA)

SUFFIXES = .pm .html

.pm.html:
	pod2html --noindex $*.pm | \
	    sed -e 's,</HEAD>,<LINK REL="stylesheet" HREF="../../../../doxygen/globus.css"></HEAD>,' > $*.html

globus-job-manager-service: globus-job-manager-service.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-job-manager-script.pl: $(srcdir)/globus-job-manager-script.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
JobDescription.pm: $(srcdir)/JobDescription.pm.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@


CLEANFILES = globus-job-manager-service globus-job-manager-script.pl JobDescription.pm
MAINTAINERCLEANFILES = $(perldoc_DATA) $(noinst_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
