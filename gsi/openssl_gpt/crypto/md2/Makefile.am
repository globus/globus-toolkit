include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	md2_dgst.c \
	md2_one.c

Test_Sources = \
	md2test.c

opensslinclude_HEADERS= \
	md2.h

noinst_LTLIBRARIES = libmd2_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libmd2___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libmd2___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libmd2___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
