include $(top_srcdir)/globus_automake_targets

Sources= \
	scutils.c \
	scutils.h \
	sslutils.c \
	sslutils.h

include_HEADERS= \
	scutils.h \
	sslutils.h

lib_LTLIBRARIES = libglobus_ssl_utils_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES)

libglobus_ssl_utils___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_ssl_utils___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIBS)
libglobus_ssl_utils___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_rules
include $(top_srcdir)/globus_automake_top_rules
