include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

INCLUDES = $(GPT_INCLUDES)

EXTRA_DIST=

flavorinclude_HEADERS= \
	globus_gridmap_callout_error.h

lib_LTLIBRARIES = libglobus_gridmap_callout_error_$(GLOBUS_FLAVOR_NAME).la

libglobus_gridmap_callout_error___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	@GPT_LIB_LINKS@
libglobus_gridmap_callout_error___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	globus_i_gridmap_callout_error.c \
	globus_gridmap_callout_error.h
libglobus_gridmap_callout_error___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
	@GPT_LDFLAGS@

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
