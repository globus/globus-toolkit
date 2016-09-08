ACLOCAL_AMFLAGS=-I m4
doc_DATA = GLOBUS_LICENSE
sysconf_DATA = gridmap_verify_myproxy_callout-gsi_authz.conf
lib_LTLIBRARIES = libglobus_gridmap_verify_myproxy_callout.la

libglobus_gridmap_verify_myproxy_callout_la_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) $(OPENSSL_CFLAGS)
libglobus_gridmap_verify_myproxy_callout_la_LDFLAGS = \
        -avoid-version \
        -no-undefined \
        -module \
        -rpath $(libdir)
libglobus_gridmap_verify_myproxy_callout_la_LIBADD = $(PACKAGE_DEP_LIBS) $(OPENSSL_LIBS)
libglobus_gridmap_verify_myproxy_callout_la_SOURCES = \
	globus_gridmap_verify_myproxy.c

EXTRA_DIST = dirt.sh $(doc_DATA) $(sysconf_DATA)
distuninstallcheck:
	@:
