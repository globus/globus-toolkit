AUTOMAKE_OPTIONS = foreign

doc_DATA = GLOBUS_LICENSE
include_HEADERS = globus_xio_gridftp_driver.h
lib_LTLIBRARIES = libglobus_xio_gridftp_driver.la

libglobus_xio_gridftp_driver_la_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)
libglobus_xio_gridftp_driver_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_xio_gridftp_driver_la_LDFLAGS = \
        -version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined
	-module -rpath $(libdir)
libglobus_xio_gridftp_driver_la_SOURCES = globus_xio_gridftp_driver.c

EXTRA_DIST = dirt.sh version.h.in $(doc_DATA)
