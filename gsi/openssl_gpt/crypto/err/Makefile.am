include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	err.c \
	err_all.c \
	err_prn.c

opensslinclude_HEADERS= \
	err.h

noinst_LTLIBRARIES = liberr_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

liberr___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

liberr___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

liberr___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
