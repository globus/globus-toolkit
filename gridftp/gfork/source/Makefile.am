ACLOCAL_AMFLAGS=-I m4
pkgconfdir = $(libdir)/pkgconfig

include_HEADERS = globus_gfork.h
lib_LTLIBRARIES = libglobus_gfork.la
sbin_PROGRAMS = $(GFORK_EXE)
doc_DATA = GLOBUS_LICENSE README.txt
pkgconf_DATA = globus-gfork.pc

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)

libglobus_gfork_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_gfork_la_LDFLAGS = \
    -version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
    -no-undefined
libglobus_gfork_la_SOURCES = \
    globus_gfork.h           \
    globus_i_gfork.h         \
    globus_gfork_lib.c       \
    globus_gfork_states.c    \
    globus_gfork_opts.c

gfork_SOURCES = globus_gfork_server.c
gfork_LDADD = libglobus_gfork.la $(PACKAGE_DEP_LIBS)

EXTRA_PROGRAMS = gfork

EXTRA_DIST = dirt.sh $(doc_DATA)

distuninstallcheck:
	@:
