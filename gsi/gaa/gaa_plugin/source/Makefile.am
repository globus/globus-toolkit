include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen


Sources = \
	gaa_plugin.c \
	gaa_plugin.h \
	default_callbacks.c \
	gaa_init.c \
	gaa_plugin_private.h

setup_DATA = \
	globus_gaa.conf \
	globus_gaa_custom.conf

INCLUDES = $(GPT_INCLUDES)

CFLAGS += -DGAA_FLAVOR_NAME=\"@GLOBUS_FLAVOR_NAME@\"

EXTRA_DIST=

flavorinclude_HEADERS= \
	gaa_plugin.h

lib_LTLIBRARIES = libglobus_gaa_plugin_$(GLOBUS_FLAVOR_NAME).la

libglobus_gaa_plugin___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gaa_plugin___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_gaa_plugin___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
