include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
    doxygen

Sources= \
	globus_grim_devel.c                 \
	globus_grim_devel.h

INCLUDES = $(GPT_INCLUDES)

flavorinclude_HEADERS= \
	globus_grim_devel.h

lib_LTLIBRARIES = libglobus_grim_devel_$(GLOBUS_FLAVOR_NAME).la

libglobus_grim_devel___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_grim_devel___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_grim_devel___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

EXTRA_DIST = \
	version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

