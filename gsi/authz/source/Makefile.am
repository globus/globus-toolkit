include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	globus_gsi_authz.c \
	globus_gsi_authz_error.c \
	globus_gsi_authz.h \
	globus_gsi_authz_constants.h \
	globus_i_gsi_authz.h

EXTRA_DIST = version.h.in

flavorinclude_HEADERS= \
	globus_gsi_authz.h


INCLUDES = $(GPT_INCLUDES) 

lib_LTLIBRARIES = libglobus_authz_$(GLOBUS_FLAVOR_NAME).la

libglobus_authz___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_authz___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_authz___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
