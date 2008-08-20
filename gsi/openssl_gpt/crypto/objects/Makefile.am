include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	o_names.c \
	obj_dat.c \
	obj_lib.c \
	obj_err.c

opensslinclude_HEADERS= \
	objects.h \
	obj_mac.h

noinst_HEADERS = \
	obj_dat.h

noinst_LTLIBRARIES = libobjects_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libobjects___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libobjects___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libobjects___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
