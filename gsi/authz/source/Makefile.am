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

doc_DATA = GLOBUS_LICENSE

EXTRA_DIST = globus-authz.spec version.h.in $(doc_DATA)

include_HEADERS= \
	globus_gsi_authz.h


INCLUDES = $(GPT_INCLUDES) 

lib_LTLIBRARIES = libglobus_authz.la

libglobus_authz_la_SOURCES = $(Sources)

libglobus_authz_la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_authz_la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
