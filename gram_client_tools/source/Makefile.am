include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# SUBDIRS is an automake macro which contains
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	pkgdata \
	doxygen

INCLUDES = $(GPT_INCLUDES)

bin_SCRIPTS = \
	globus-job-run \
	globus-job-status \
	globus-job-clean \
	globus-job-get-output \
	globus-job-get-output-helper \
	globus-job-submit \
	globus-job-cancel

# EXTRA_DIST is used to include files in
# a source distribution that automake fails to detect.
EXTRA_DIST = globus-job-run.in \
	     globus-job-status.in \
	     globus-job-clean.in \
	     globus-job-get-output.in \
	     globus-job-get-output-helper \
	     version.h.in \
	     dirt.sh

bin_PROGRAMS = globusrun

globusrun_SOURCES = globusrun.c

globusrun_LDFLAGS = $(GPT_LDFLAGS)
globusrun_LDADD = $(GPT_PGM_LINKS)

## man1dir = [ DOC ]
man1_MANS = globus-job-cancel.1 \
                globus-job-clean.1 \
                globus-job-get-output.1 \
                globus-job-run.1  \
                globus-job-status.1 \
                globus-job-submit.1 \
                globusrun.1

MANUAL_SOURCE = globus-job-cancel-manual.xml \
                globus-job-clean-manual.xml \
                globus-job-get-output-manual.xml \
                globus-job-get-output-helper-manual.xml \
                globus-job-run-manual.xml \
                globus-job-status-manual.xml \
                globus-job-submit-manual.xml \
                globusrun-manual.xml \
                manual.xml

if GENERATE_MANPAGES
export XML_CATALOG_FILES :=  $(XML_CATALOG_PATH)

$(man1_MANS): $(MANUAL_SOURCE)
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd manual.xml > /dev/null
	$(XSLTPROC) --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl manual.xml
endif

DISTCLEANFILES = version.h

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

