include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	ocsp_asn.c ocsp_ext.c ocsp_ht.c ocsp_lib.c ocsp_cl.c \
	ocsp_srv.c ocsp_prn.c ocsp_vfy.c ocsp_err.c


opensslinclude_HEADERS= \
	ocsp.h

noinst_LTLIBRARIES = libocsp_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libocsp___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libocsp___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

libocsp___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)


include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post


