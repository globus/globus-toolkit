noinst_LTLIBRARIES = libglobus_rvf.la
sbin_PROGRAMS = globus-rvf-check
sbin_SCRIPTS = globus-rvf-edit
man_MANS = globus-rvf-edit.8 globus-rvf-check.8

AM_YFLAGS = -d

BUILT_SOURCES = globus_i_rvf_parser.c globus_i_rvf_parser.h globus_i_rvf_scanner.c globus_i_rvf_scanner.h
AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -DYY_NO_INPUT -I$(top_srcdir)
libglobus_rvf_la_SOURCES = \
    globus_i_rvf_scanner.l \
    globus_i_rvf_parser.y \
    globus_i_rvf.h \
    globus_rvf_parser.h

globus_rvf_check_SOURCES = globus_rvf_check.c
globus_rvf_check_LDADD = \
	libglobus_rvf.la $(PACKAGE_DEP_LIBS)


EXTRA_DIST = $(man_MANS) \
    globus-rvf-edit.txt \
    globus-rvf-check.txt \
    globus_i_rvf_scanner.c \
    globus_i_rvf_scanner.h \
    globus_i_rvf_parser.c \
    globus_i_rvf_parser.h

if BUILD_MANPAGES
SUFFIXES = .txt .8

.txt.8:
	$(A2X) -d manpage -f manpage $<

MAINTAINERCLEANFILES = $(man_MANS)
endif
