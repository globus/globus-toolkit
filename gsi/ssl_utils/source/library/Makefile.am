include $(top_srcdir)/globus_automake_pre

SUBDIRS = oldgaa

Sources= \
	scutils.c \
	scutils.h \
	sslutils.c \
	sslutils.h \
	module.c

flavorinclude_HEADERS= \
	scutils.h \
	sslutils.h

lib_LTLIBRARIES = libglobus_ssl_utils_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES) -I$(top_srcdir)/library/oldgaa -I./oldgaa

#AM_CFLAGS = -DDEBUG

libglobus_ssl_utils___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_ssl_utils___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) \
	./oldgaa/libglobus_oldgaa_$(GLOBUS_FLAVOR_NAME).la

libglobus_ssl_utils___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post
