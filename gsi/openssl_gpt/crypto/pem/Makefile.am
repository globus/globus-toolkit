include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	pem_sign.c \
	pem_seal.c \
	pem_info.c \
	pem_lib.c \
	pem_all.c \
	pem_err.c \
	pem_x509.c \
	pem_xaux.c \
	pem_oth.c \
	pem_pk8.c \
	pem_pkey.c

opensslinclude_HEADERS= \
	pem.h \
	pem2.h

noinst_LTLIBRARIES = libpem_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libpem___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libpem___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libpem___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
