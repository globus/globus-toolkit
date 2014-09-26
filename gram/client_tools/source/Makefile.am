ACLOCAL_AMFLAGS=-I m4
SUBDIRS = .

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

globusrun_SOURCES = globusrun.c

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)
globusrun_LDADD = $(PACKAGE_DEP_LIBS)


MANUAL_SOURCE = globus-job-cancel.txt \
                globus-job-clean.txt \
                globus-job-get-output.txt \
                globus-job-get-output-helper.txt \
                globus-job-run.txt \
                globus-job-status.txt \
                globus-job-submit.txt \
                globusrun.txt \
                globus-job-cancel.xml \
                globus-job-clean.xml \
                globus-job-get-output.xml \
                globus-job-get-output-helper.xml \
                globus-job-run.xml \
                globus-job-status.xml \
                globus-job-submit.xml \
                globusrun.xml

# EXTRA_DIST is used to include files in
# a source distribution that automake fails to detect.
EXTRA_DIST = globus-job-get-output-helper \
	     $(man_MANS) \
	     $(MANUAL_SOURCE) \
	     $(doc_DATA) \
	     dirt.sh

if BUILD_MANPAGES
SUFFIXES = .xml .1

if HAVE_A2X
SUFFIXES += .txt
.txt.xml:
	$(A2X) -f docbook -d manpage $<
endif

.xml.1:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) `test -f $< && echo $< || echo $(srcdir)/$<` > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) `test -f $< && echo $< || echo $(srcdir)/$<`
MAINTAINERCLEANFILES = $(man_MANS)
endif

distuninstallcheck:
	@:
