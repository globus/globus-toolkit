SUBDIRS = .
BUILT_SOURCES = version.h

bin_PROGRAMS = globusrun
bin_SCRIPTS = \
	globus-job-run \
	globus-job-status \
	globus-job-clean \
	globus-job-get-output \
	globus-job-get-output-helper \
	globus-job-submit \
	globus-job-cancel
man_MANS = globus-job-cancel.1 \
                globus-job-clean.1 \
                globus-job-get-output.1 \
                globus-job-run.1  \
                globus-job-status.1 \
                globus-job-submit.1 \
                globusrun.1
doc_DATA = GLOBUS_LICENSE

globusrun_SOURCES = globusrun.c version.h

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)
globusrun_LDADD = $(PACKAGE_DEP_LIBS)


MANUAL_SOURCE = globus-job-cancel.xml \
                globus-job-clean.xml \
                globus-job-get-output.xml \
                globus-job-get-output-helper.xml \
                globus-job-run.xml \
                globus-job-status.xml \
                globus-job-submit.xml \
                globusrun.xml

# EXTRA_DIST is used to include files in
# a source distribution that automake fails to detect.
EXTRA_DIST = globus-job-run.in \
	     globus-job-status.in \
	     globus-job-clean.in \
	     globus-job-get-output.in \
	     globus-job-get-output-helper \
	     version.h.in \
	     $(man_MANS) \
	     $(MANUAL_SOURCE) \
	     $(doc_DATA) \
	     dirt.sh

if BUILD_MANPAGES
SUFFIXES = .xml .1

.xml.1:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) $<
MAINTAINERCLEANFILES = $(man_MANS)
endif

distuninstallcheck:
	@:
