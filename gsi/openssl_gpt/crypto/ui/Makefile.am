include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	ui_err.c \
	ui_lib.c \
	ui_openssl.c \
	ui_util.c \
	ui_compat.c

opensslinclude_HEADERS= \
	ui.h \
	ui_compat.h

noinst_HEADERS = \
	ui_locl.h

noinst_LTLIBRARIES = libui_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libui___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libui___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

libui___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)


include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post


