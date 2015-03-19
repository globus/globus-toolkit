pkgconfigdir = $(libdir)/pkgconfig

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -DGLOBUS_BUILTIN=1
include_HEADERS = globus_xio_mode_g_connection_driver.h
lib_LTLIBRARIES = libglobus_xio_mode_g_connection_driver.la
libglobus_xio_mode_g_connection_driver_la_SOURCES = \
    globus_xio_mode_g_connection_driver.c \
    globus_xio_mode_g_connection_driver.h
libglobus_xio_mode_g_connection_driver_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_xio_mode_g_connection_driver_la_LDFLAGS = \
    -avoid-version \
    -module \
    -no-undefined

EXTRA_DIST = \
    connection_driver.md \
    connection_states.md \
    connection_states.svg \
    connection_states.txt \
    flow_states.md \
    flow_states.svg \
    flow_states.txt
