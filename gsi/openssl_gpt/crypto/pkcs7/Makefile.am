include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	pk7_lib.c \
	pkcs7err.c \
	pk7_doit.c \
	pk7_smime.c \
	pk7_attr.c \
	pk7_mime.c \
	pk7_asn1.c

opensslinclude_HEADERS= \
	pkcs7.h

noinst_LTLIBRARIES = libpkcs7_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libpkcs7___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libpkcs7___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libpkcs7___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
