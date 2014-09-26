ACLOCAL_AMFLAGS=-I m4
SUBDIRS = . test

pkgconfigdir = $(libdir)/pkgconfig

include_HEADERS = \
	globus_io.h \
	globus_io_error_hierarchy.h
lib_LTLIBRARIES = libglobus_io.la
doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-io.pc

libglobus_io_la_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) $(GSI_DRIVER_CFLAGS)

libglobus_io_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_io_la_LDFLAGS = \
        -version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined
libglobus_io_la_SOURCES = \
	globus_io.h \
	globus_io_error_hierarchy.c \
	globus_io_error_hierarchy.h \
	globus_io_xio_compat.c

EXTRA_DIST = dirt.sh $(doc_DATA)

distuninstallcheck:
	@:
