AUTOMAKE_OPTIONS = foreign

pkgconfigdir = $(libdir)/pkgconfig

include_HEADERS = globus_xio_pipe_driver.h
lib_LTLIBRARIES = libglobus_xio_pipe_driver.la
doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-xio-pipe-driver.pc

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)
libglobus_xio_pipe_driver_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_xio_pipe_driver_la_SOURCES = globus_xio_pipe_driver.c
libglobus_xio_pipe_driver_la_LDFLAGS = \
	-version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined \
        -module -rpath $(libdir)

EXTRA_DIST = dirt.sh version.h.in $(doc_DATA)
