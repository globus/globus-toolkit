include $(top_srcdir)/globus_automake_config
include $(top_srcdir)/globus_automake_targets

Sources= \
	scutils.c \
	scutils.h \
	sslutils.c \
	sslutils.h \
	gaa/gaa_alloc.c \
	gaa/gaa_api.c \
	gaa/gaa_gl_internal_err.c \
	gaa/gaa_gl_internal_err.h \
	gaa/gaa_policy_evaluator.c \
	gaa/gaa_policy_evaluator.h \
	gaa/gaa_release.c \
	gaa/gaa_utils.c \
	gaa/gaa_utils.h \
	gaa/globus_common.h \
	gaa/globus_gaa.h \
	gaa/globus_gaa_utils.c \
	gaa/globus_gaa_utils.h \
	gaa/gnu_regex.c \
	gaa/gnu_regex.h \
	gaa/rfc1779.c

include_HEADERS= \
	scutils.h \
	sslutils.h

lib_LTLIBRARIES = libglobus_ssl_utils_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES)

AM_CFLAGS = -DDEBUG

libglobus_ssl_utils___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_ssl_utils___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIBS)
libglobus_ssl_utils___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_rules
