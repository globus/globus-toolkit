include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	p12_add.c \
	p12_asn.c \
	p12_attr.c \
	p12_crpt.c \
	p12_crt.c \
	p12_decr.c \
	p12_init.c \
	p12_key.c \
	p12_kiss.c \
	p12_mutl.c\
	p12_utl.c \
	p12_npas.c \
	pk12err.c \
	p12_p8d.c \
	p12_p8e.c

opensslinclude_HEADERS= \
	pkcs12.h

noinst_LTLIBRARIES = libpkcs12_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libpkcs12___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libpkcs12___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libpkcs12___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
