include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	krb5_asn.c

opensslinclude_HEADERS= \
	krb5_asn.h

noinst_LTLIBRARIES = libkrb5_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libkrb5___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libkrb5___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

libkrb5___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)


include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post


