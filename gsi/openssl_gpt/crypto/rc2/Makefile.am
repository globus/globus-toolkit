include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	rc2_ecb.c \
	rc2_skey.c \
	rc2_cbc.c \
	rc2cfb64.c \
	rc2ofb64.c

Test_Sources = \
	rc2test.c

opensslinclude_HEADERS= \
	rc2.h

noinst_HEADERS = \
	rc2_locl.h

noinst_LTLIBRARIES = librc2_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

librc2___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

librc2___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

librc2___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
