SUBDIRS = pkgdata doxygen

lib_LTLIBRARIES = libglobus_gridmap_callout.la

AM_CPPFLAGS = $(GPT_INCLUDES)
AM_LIBADD = $(GPT_LIB_LINKS)
AM_LDFLAGS = $(GPT_LDFLAGS) -module -rpath $(libdir)

libglobus_gridmap_callout_la_SOURCES = globus_gridmap_callout.c

EXTRA_DIST = dirt.sh
