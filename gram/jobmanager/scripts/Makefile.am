include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata

libexec_SCRIPTS = globus-job-manager-script.pl
sbin_SCRIPTS = globus-gatekeeper-admin

# Extra directories we install files into
globusperldir=$(perlmoduledir)/Globus/GRAM
perldocdir=$(docdir)/perl/Globus/GRAM

# Where targets are installed
globusperl_DATA = \
    JobDescription.pm \
    JobManager.pm \
    StdioMerger.pm
perldoc_DATA = JobManager.html JobDescription.html

doc_DATA = GLOBUS_LICENSE

# Files which we want to put in the source package
EXTRA_DIST = globus-job-manager-script.pl.in \
            JobDescription.pm.in \
            JobManager.pm StdioMerger.pm $(perldoc_DATA) \
	    $(doc_DATA)

SUFFIXES = .pm .html

.pm.html:
	pod2html --noindex $*.pm > $*.html

MAINTAINERCLEANFILES = $(perldoc_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
