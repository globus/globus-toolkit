include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	util.c \
	gaa_util.h 

INCLUDES = $(GPT_INCLUDES)

EXTRA_DIST=

flavorinclude_HEADERS= \
	gaa_util.h

lib_LTLIBRARIES = libglobus_gaa_util_$(GLOBUS_FLAVOR_NAME).la

libglobus_gaa_util___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gaa_util___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_gaa_util___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
