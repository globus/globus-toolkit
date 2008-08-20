include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	globus_gsi_authz_callout_error.h \
	globus_gsi_authz_callout_error.c

EXTRA_DIST = version.h.in

flavorinclude_HEADERS= \
	globus_gsi_authz_callout_error.h


INCLUDES = $(GPT_INCLUDES) 

lib_LTLIBRARIES = libglobus_gsi_authz_callout_error_$(GLOBUS_FLAVOR_NAME).la

libglobus_gsi_authz_callout_error___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gsi_authz_callout_error___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_gsi_authz_callout_error___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
