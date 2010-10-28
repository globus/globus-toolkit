include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

INCLUDES = $(GPT_INCLUDES)

EXTRA_DIST=

lib_LTLIBRARIES = libglobus_gridmap_callout.la

libglobus_gridmap_callout_la_LIBADD = \
	@GPT_LIB_LINKS@
libglobus_gridmap_callout_la_SOURCES = \
	globus_gridmap_callout.c
libglobus_gridmap_callout_la_LDFLAGS = \
	@GPT_LDFLAGS@ -module -rpath $(libdir)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
