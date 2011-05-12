include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	gaa_debug.c \
	gaa_debug.h 

INCLUDES = $(GPT_INCLUDES)

EXTRA_DIST=

include_HEADERS= \
	gaa_debug.h

lib_LTLIBRARIES = libglobus_gaa_debug.la

libglobus_gaa_debug_la_SOURCES = $(Sources)

libglobus_gaa_debug_la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_gaa_debug_la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
