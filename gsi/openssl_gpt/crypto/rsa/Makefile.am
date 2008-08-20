include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	rsa_eay.c \
	rsa_gen.c \
	rsa_lib.c \
	rsa_sign.c \
	rsa_saos.c \
	rsa_err.c \
	rsa_pk1.c \
	rsa_ssl.c \
	rsa_none.c \
	rsa_oaep.c \
	rsa_chk.c \
	rsa_null.c \
	rsa_asn1.c

Test_Sources = \
	rsa_test.c

opensslinclude_HEADERS= \
	rsa.h

noinst_LTLIBRARIES = librsa_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

librsa___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

librsa___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

librsa___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
