pkgconfigdir = $(libdir)/pkgconfig

include_HEADERS = globus_xio_gridftp_multicast_driver.h
lib_LTLIBRARIES = libglobus_xio_gridftp_multicast_driver.la
pkgconfig_DATA = globus-xio-gridftp-multicast.pc

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)

libglobus_xio_gridftp_multicast_driver_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_xio_gridftp_multicast_driver_la_SOURCES = \
	globus_xio_gridftp_multicast_driver.c
libglobus_xio_gridftp_multicast_driver_la_LDFLAGS = \
	-version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined
	-module -rpath $(libdir)

EXTRA_DIST = dirt.sh version.h.in

distuninstallcheck:
	@:
