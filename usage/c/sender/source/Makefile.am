AUTOMAKE_OPTIONS = foreign

pkgconfigdir = $(libdir)/pkgconfig

include_HEADERS = globus_usage.h
lib_LTLIBRARIES = libglobus_usage.la 
doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-usage.pc

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)

libglobus_usage_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_usage_la_LDFLAGS = \
    -version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
    -no-undefined
libglobus_usage_la_SOURCES = globus_usage.c

EXTRA_DIST = dirt.sh $(doc_DATA)
