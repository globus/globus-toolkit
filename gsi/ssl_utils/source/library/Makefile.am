include $(top_srcdir)/globus_automake_config
include $(top_srcdir)/globus_automake_targets

SUBDIRS = gaa

Sources= \
	scutils.c \
	scutils.h \
	sslutils.c \
	sslutils.h

include_HEADERS= \
	scutils.h \
	sslutils.h

lib_LTLIBRARIES = libglobus_ssl_utils_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES) -I $top_srcdir/library/gaa -I ./gaa

AM_CFLAGS = -DDEBUG

libglobus_ssl_utils___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_ssl_utils___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) \
	./gaa/libglobus_gaa_$(GLOBUS_FLAVOR_NAME).la

libglobus_ssl_utils___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_rules
