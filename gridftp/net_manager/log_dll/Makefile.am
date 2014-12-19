pkgconfigdir = $(libdir)/pkgconfig

lib_LTLIBRARIES = libglobus_net_manager_log.la
doc_DATA = GLOBUS_LICENSE
#pkgconfig_DATA = globus_net_manager_log.pc

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)
libglobus_net_manager_log_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_net_manager_log_la_SOURCES = globus_net_manager_log.c globus_net_manager_log.h
libglobus_net_manager_log_la_LDFLAGS = \
        -no-undefined \
        -avoid-version \
        -module -rpath $(libdir)

EXTRA_DIST = dirt.sh $(doc_DATA)

distuninstallcheck:
	@:
