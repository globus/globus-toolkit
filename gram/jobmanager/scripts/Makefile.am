AUTOMAKE_OPTIONS = foreign

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
        globus-job-manager-script.pl.in \
        JobDescription.pm.in \
        JobManager.pm \
        StdioMerger.pm \
        $(perldoc_DATA) \
        globus-gatekeeper-admin.xml \
        globus-gatekeeper-admin.8 \
	$(doc_DATA)

SUFFIXES = .pm .html

.pm.html:
	pod2html --noindex $< > $@

MAINTAINERCLEANFILES = $(perldoc_DATA)


if BUILD_MANPAGES
SUFFIXES += .xml .8

.xml.8:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) $<
CLEANFILES = $(man_MANS)
endif
