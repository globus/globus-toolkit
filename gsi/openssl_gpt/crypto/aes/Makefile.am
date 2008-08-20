include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	aes_core.c \
	aes_misc.c \
	aes_ecb.c \
	aes_cbc.c \
	aes_cfb.c \
	aes_ofb.c \
	aes_ctr.c

opensslinclude_HEADERS= \
	aes.h

noinst_HEADERS = \
	aes_locl.h

noinst_LTLIBRARIES = libaes_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir)/include $(GPT_INCLUDES)

libaes___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libaes___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

libaes___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)


include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post


