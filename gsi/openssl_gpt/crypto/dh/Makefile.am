include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	dh_gen.c \
	dh_key.c \
	dh_lib.c \
	dh_check.c \
	dh_err.c \
	dh_asn1.c

Test_Sources = \
	dhtest.c

opensslinclude_HEADERS= \
	dh.h

noinst_LTLIBRARIES = libdh_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libdh___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libdh___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libdh___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
