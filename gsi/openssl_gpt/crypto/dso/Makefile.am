include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	dso_dl.c \
	dso_dlfcn.c \
	dso_err.c \
	dso_lib.c \
	dso_null.c \
	dso_openssl.c \
	dso_win32.c \
	dso_vms.c

opensslinclude_HEADERS= \
	dso.h

noinst_LTLIBRARIES = libdso_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libdso___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libdso___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libdso___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post
