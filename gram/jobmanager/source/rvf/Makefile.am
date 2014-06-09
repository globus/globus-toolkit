noinst_LTLIBRARIES = libglobus_rvf.la
sbin_PROGRAMS = globus-rvf-check
sbin_SCRIPTS = globus-rvf-edit
man_MANS = globus-rvf-edit.8 globus-rvf-check.8

AM_YFLAGS = -d

BUILT_SOURCES = globus_i_rvf_parser.c globus_i_rvf_parser.h globus_i_rvf_scanner.c globus_i_rvf_scanner.h
AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_srcdir)
libglobus_rvf_la_SOURCES = \
    globus_i_rvf_scanner.l \
    globus_i_rvf_parser.y \
    globus_i_rvf.h \
    globus_rvf_parser.h

globus_rvf_check_SOURCES = globus_rvf_check.c
globus_rvf_check_LDADD = \
	libglobus_rvf.la $(PACKAGE_DEP_LIBS)


EXTRA_DIST = globus-rvf-edit $(man_MANS) \
    globus-rvf-edit.xml \
    globus-rvf-check.xml \
    globus_i_rvf_scanner.c \
    globus_i_rvf_scanner.h \
    globus_i_rvf_parser.c \
    globus_i_rvf_parser.h

if BUILD_MANPAGES
SUFFIXES = .xml .8

.xml.8:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) $<
MAINTAINERCLEANFILES = $(man_MANS)
endif
