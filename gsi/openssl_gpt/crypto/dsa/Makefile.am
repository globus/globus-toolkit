include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	dsa_gen.c \
	dsa_key.c \
	dsa_lib.c \
	dsa_asn1.c \
	dsa_vrf.c \
	dsa_sign.c \
	dsa_err.c \
	dsa_ossl.c

Test_Sources = \
	dsatest.c

opensslinclude_HEADERS= \
	dsa.h

noinst_LTLIBRARIES = libdsa_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libdsa___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libdsa___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libdsa___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post






