AUTOMAKE_OPTIONS = foreign

pkgconfigdir = $(libdir)/pkgconfig

bin_PROGRAMS = globus-xioperf
doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-xioperf.pc

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)

globus_xioperf_LDADD = $(PACKAGE_DEP_LIBS)
globus_xioperf_SOURCES = \
    globus_i_xioperf.h \
    globus_xioperf.c  \
    globus_i_xioperf_opts.c

EXTRA_DIST = dirt.sh version.h.in $(doc_DATA)
