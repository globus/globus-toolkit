include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# SUBDIRS is an automake macro which contains 
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	pkgdata

Sources= \
	globus_grim_devel.c \
	globus_grim_devel.h

INCLUDES += $(GPT_INCLUDES)

flavorinclude_HEADERS= globus_grim_devel.h

lib_LTLIBRARIES = libglobus_ftp_control_$(GLOBUS_FLAVOR_NAME).la
libglobus_grim_devel___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_grim_devel___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_grim_devel___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

EXTRA_DIST = \
	version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
