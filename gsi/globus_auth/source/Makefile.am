include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	globus_auth.c \
	globus_auth.h \
	globus_auth_error.c \
	globus_auth_error.h \
	temp.h

INCLUDES += $(GPT_INCLUDES)

flavorinclude_HEADERS= \
	globus_auth.h \
	globus_auth_error.h 

lib_LTLIBRARIES = libglobus_auth_$(GLOBUS_FLAVOR_NAME).la

libglobus_auth___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_auth___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_auth___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
