include_HEADERS = globus_xio_ordering_driver.h    
noinst_LTLIBRARIES = libglobus_xio_ordering_driver.la 

AM_CPPFLAGS = \
    -I$(top_srcdir) \
    -I$(top_srcdir)/builtins/udp \
    -I$(top_srcdir)/builtins/tcp \
    -DGLOBUS_BUILTIN=1 \
    $(PACKAGE_DEP_CFLAGS)
AM_LDFLAGS = $(PACKAGE_DEP_LIBS)

libglobus_xio_ordering_driver_la_SOURCES = globus_xio_ordering_driver.c
