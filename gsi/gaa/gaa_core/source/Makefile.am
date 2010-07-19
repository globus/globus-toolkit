include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	gaa.c \
	gaa_authinfo.c \
	gaa_core.h \
	gaa_mutex.c \
	gaa_private.h \
	gaa_util.c \
	gaa.h \
	gaa_constants.h \
	gaa_list.c \
	gaa_policy.c \
	gaa_str.c

INCLUDES = $(GPT_INCLUDES)

EXTRA_DIST=

flavorinclude_HEADERS= \
	gaa.h \
	gaa_constants.h \
	gaa_core.h

lib_LTLIBRARIES = libglobus_gaa_core_$(GLOBUS_FLAVOR_NAME).la

libglobus_gaa_core___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gaa_core___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_gaa_core___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
