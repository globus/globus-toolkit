globusperldir=$(perlmoduledir)/Globus/GRAM
perldocdir=$(docdir)/perl/Globus/GRAM

libexec_SCRIPTS = globus-job-manager-script.pl
sbin_SCRIPTS = globus-gatekeeper-admin
globusperl_DATA = \
    JobDescription.pm \
    JobManager.pm \
    StdioMerger.pm
perldoc_DATA = JobManager.html JobDescription.html
doc_DATA = GLOBUS_LICENSE
man_MANS = globus-gatekeeper-admin.8
BUILT_SOURCES = JobDescription.pm

# Files which we want to put in the source package
EXTRA_DIST = \
        dirt.sh \
        $(globusperl_DATA) \
        $(perldoc_DATA) \
        globus-gatekeeper-admin.txt \
        globus-gatekeeper-admin.8 \
	$(doc_DATA)

SUFFIXES = .pm .html

.pm.html:
	pod2html --noindex $< > $@

MAINTAINERCLEANFILES = $(perldoc_DATA)

all-local:
	$(MKDIR_P) Globus/GRAM
	$(INSTALL) $(srcdir)/JobDescription.pm Globus/GRAM
	$(INSTALL) $(srcdir)/JobManager.pm Globus/GRAM
	$(INSTALL) $(srcdir)/StdioMerger.pm Globus/GRAM

clean-local:
	rm -rf Globus
if BUILD_MANPAGES
SUFFIXES += .txt .8

.txt.8:
	$(A2X) -d manpage -f manpage $<
MAINTAINERCLEANFILES += $(man_MANS)
endif

distuninstallcheck:
	@:
