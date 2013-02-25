include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata 

Sources = globus_gridmap_eppn.c
	
doc_DATA = GLOBUS_LICENSE

EXTRA_DIST = version.h.in $(doc_DATA)

INCLUDES = $(GPT_INCLUDES) 

sysconf_DATA = gridmap_eppn_callout-gsi_authz.conf

lib_LTLIBRARIES = libglobus_gridmap_eppn_callout.la

libglobus_gridmap_eppn_callout_la_SOURCES = $(Sources)

libglobus_gridmap_eppn_callout_la_LDFLAGS = $(GPT_LDFLAGS) -module

libglobus_gridmap_eppn_callout_la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
