include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	md4_dgst.c \
	md4_one.c

Test_Sources = \
	md4test.c

opensslinclude_HEADERS= \
	md4.h

noinst_HEADERS = \
	md4_locl.h

noinst_LTLIBRARIES = libmd4_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libmd4___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libmd4___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libmd4___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
