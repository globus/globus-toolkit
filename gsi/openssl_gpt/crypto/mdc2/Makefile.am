include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	mdc2dgst.c \
	mdc2_one.c

Test_Sources = \
	mdc2test.c

opensslinclude_HEADERS= \
	mdc2.h

noinst_LTLIBRARIES = libmdc2_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libmdc2___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libmdc2___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libmdc2___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
