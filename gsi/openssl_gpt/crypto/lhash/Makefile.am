include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	lhash.c \
	lh_stats.c

opensslinclude_HEADERS= \
	lhash.h

noinst_LTLIBRARIES = liblhash_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

liblhash___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

liblhash___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

liblhash___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
