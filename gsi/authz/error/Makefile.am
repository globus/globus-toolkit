include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	globus_gsi_authz_callout_error.h \
	globus_gsi_authz_callout_error.c

doc_DATA = GLOBUS_LICENSE

EXTRA_DIST = version.h.in $(doc_DATA)

include_HEADERS= \
	globus_gsi_authz_callout_error.h


INCLUDES = $(GPT_INCLUDES) 

lib_LTLIBRARIES = libglobus_gsi_authz_callout_error.la

libglobus_gsi_authz_callout_error_la_SOURCES = $(Sources)

libglobus_gsi_authz_callout_error_la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_gsi_authz_callout_error_la_LIBADD = $(GPT_LIB_LINKS)


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
