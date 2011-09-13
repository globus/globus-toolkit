include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

INCLUDES = $(GPT_INCLUDES)

doc_DATA = GLOBUS_LICENSE

EXTRA_DIST= $(doc_DATA)


include_HEADERS= \
	globus_gridmap_callout_error.h

lib_LTLIBRARIES = libglobus_gridmap_callout_error.la

libglobus_gridmap_callout_error_la_LIBADD = \
	@GPT_LIB_LINKS@
libglobus_gridmap_callout_error_la_SOURCES = \
	globus_i_gridmap_callout_error.c \
	globus_gridmap_callout_error.h
libglobus_gridmap_callout_error_la_LDFLAGS = \
	@GPT_LDFLAGS@

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
