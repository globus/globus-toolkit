include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	conf_err.c \
	conf_lib.c \
	conf_api.c \
	conf_def.c \
	conf_mod.c \
	conf_mall.c \
	conf_sap.c

opensslinclude_HEADERS= \
	conf.h \
	conf_api.h 

noinst_HEADERS = \
	conf_def.h

noinst_LTLIBRARIES = libconf_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libconf___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libconf___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libconf___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = README

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
