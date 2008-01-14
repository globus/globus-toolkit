include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources = \
	md_rand.c \
	randfile.c \
	rand_lib.c \
	rand_err.c \
	rand_egd.c \
	rand_win.c \
	rand_unix.c \
	rand_os2.c

Test_Sources = \
	randtest.c

opensslinclude_HEADERS = \
	rand.h

noinst_HEADERS = \
	rand_lcl.h

noinst_LTLIBRARIES = librand_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

librand___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

librand___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

librand___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
