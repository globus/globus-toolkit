include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = globus_gridmap_forced_myproxy_callout.c
	
EXTRA_DIST = version.h.in

INCLUDES = $(GPT_INCLUDES) 

sysconf_DATA = gridmap_forced_myproxy_callout-gsi_authz.conf

lib_LTLIBRARIES = libglobus_gridmap_forced_myproxy_callout_$(GLOBUS_FLAVOR_NAME).la

libglobus_gridmap_forced_myproxy_callout___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gridmap_forced_myproxy_callout___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS) -module

libglobus_gridmap_forced_myproxy_callout___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
