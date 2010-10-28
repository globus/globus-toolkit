include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	globus_gsi_authz_gaa_callout.c \
	globus_i_gsi_authz_gaa_callout.h

EXTRA_DIST = version.h.in

INCLUDES = $(GPT_INCLUDES) 

lib_LTLIBRARIES = libglobus_authz_gaa_callout.la

libglobus_authz_gaa_callout_la_SOURCES = $(Sources)

libglobus_authz_gaa_callout_la_LDFLAGS = $(GPT_LDFLAGS) -module

libglobus_authz_gaa_callout_la_LIBADD = $(GPT_LIB_LINKS)


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
