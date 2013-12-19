include_HEADERS = globus_xio_udp_driver.h 
noinst_LTLIBRARIES = libglobus_xio_udp_driver.la 

AM_CPPFLAGS = -I$(top_srcdir) -DGLOBUS_BUILTIN=1 $(PACKAGE_DEP_CFLAGS) 
AM_LDFLAGS = $(PACKAGE_DEP_LIBS)

libglobus_xio_udp_driver_la_SOURCES = globus_xio_udp_driver.c
