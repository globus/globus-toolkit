include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	i_ecb.c \
	i_skey.c \
	i_cbc.c \
	i_cfb64.c \
	i_ofb64.c

Test_Sources = \
	ideatest.c

opensslinclude_HEADERS= \
	idea.h

noinst_HEADERS = \
	idea_lcl.h

noinst_LTLIBRARIES = libidea_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libidea___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libidea___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libidea___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post



