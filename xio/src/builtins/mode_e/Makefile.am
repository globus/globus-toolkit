include_HEADERS = globus_xio_mode_e_driver.h    
noinst_LTLIBRARIES = libglobus_xio_mode_e_driver.la 

AM_CPPFLAGS = -I$(top_srcdir) -DGLOBUS_BUILTIN=1 -I$(top_srcdir)/builtins/udp \
              -I$(top_srcdir)/builtins/tcp $(PACKAGE_DEP_CFLAGS)
AM_LDFLAGS = $(PACKAGE_DEP_LIBS)

libglobus_xio_mode_e_driver_la_SOURCES = globus_xio_mode_e_driver.c
