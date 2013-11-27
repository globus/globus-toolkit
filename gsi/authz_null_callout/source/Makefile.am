AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libglobus_authz_null_callout.la

libglobus_authz_null_callout_la_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)
libglobus_authz_null_callout_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_authz_null_callout_la_LDFLAGS = \
        -version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined
libglobus_authz_null_callout_la_SOURCES = \
	globus_gsi_authz_null_callout.c \
	globus_i_gsi_authz_null_callout.h

EXTRA_DIST = dirt.sh version.h.in
