include_HEADERS = globus_xio_netlogger.h
lib_LTLIBRARIES = libglobus_xio_netlogger_driver.la \
               libclient_netlogger_plugin.la

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) 
LIBADD = $(PACKAGE_DEP_LIBS)

libclient_netlogger_plugin_la_SOURCES = globus_ftp_client_nl_plugin.c
libclient_netlogger_plugin_la_LDFLAGS = \
	-version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined \
        -module \
        -rpath $(libdir)

libglobus_xio_netlogger_driver_la_SOURCES = globus_xio_netlogger.c
libglobus_xio_netlogger_driver_la_LDFLAGS = \
	-version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined \
	-module \
        -rpath $(libdir)

EXTRA_DIST = dirt.sh version.h.in

distuninstallcheck:
	@:
