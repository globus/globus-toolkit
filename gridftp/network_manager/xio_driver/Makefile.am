pkgconfigdir = $(libdir)/pkgconfig

include_HEADERS = globus_xio_net_manager_driver.h
lib_LTLIBRARIES = libglobus_xio_net_manager_driver.la
pkgconfig_DATA = globus-xio-net-manager-driver.pc

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_builddir) -I$(top_srcdir)/attr -I$(top_srcdir)/context $(PACKAGE_DEP_CFLAGS) 
libglobus_xio_net_manager_driver_la_LIBADD = \
        ../libglobus_net_manager.la $(PACKAGE_DEP_LIBS)
libglobus_xio_net_manager_driver_la_SOURCES = \
        globus_xio_net_manager_driver.c \
        globus_xio_net_manager_driver.h
libglobus_xio_net_manager_driver_la_LDFLAGS = \
        -avoid-version \
        -no-undefined \
	-module -rpath $(libdir)

distuninstallcheck:
	@:
