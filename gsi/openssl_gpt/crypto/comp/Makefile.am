include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	comp_lib.c \
	comp_err.c \
	c_rle.c \
	c_zlib.c

opensslinclude_HEADERS= \
	comp.h

noinst_LTLIBRARIES = libcomp_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libcomp___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libcomp___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libcomp___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
