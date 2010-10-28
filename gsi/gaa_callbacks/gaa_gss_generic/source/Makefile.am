include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	authgss.c \
	gaa_gss_generic.h 

INCLUDES = $(GPT_INCLUDES)

include_HEADERS= \
	gaa_gss_generic.h

lib_LTLIBRARIES = libglobus_gaa_gss_generic.la

libglobus_gaa_gss_generic_la_SOURCES = $(Sources)

libglobus_gaa_gss_generic_la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_gaa_gss_generic_la_LIBADD = $(GPT_LIB_LINKS)

EXTRA_DIST=

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
