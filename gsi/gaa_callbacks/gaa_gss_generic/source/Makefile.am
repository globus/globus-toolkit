include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	authgss.c \
	gaa_gss_generic.h 

INCLUDES = $(GPT_INCLUDES)

flavorinclude_HEADERS= \
	gaa_gss_generic.h

lib_LTLIBRARIES = libglobus_gaa_gss_generic_$(GLOBUS_FLAVOR_NAME).la

libglobus_gaa_gss_generic___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gaa_gss_generic___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_gaa_gss_generic___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

EXTRA_DIST=

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
