include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	stack.c

opensslinclude_HEADERS= \
	stack.h \
	safestack.h

noinst_LTLIBRARIES = libstack_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libstack___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libstack___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libstack___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
