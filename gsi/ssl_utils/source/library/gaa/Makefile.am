include $(top_srcdir)/globus_automake_config
include $(top_srcdir)/globus_automake_targets

Sources= \
	gaa_alloc.c \
	gaa_api.c \
	gaa_gl_internal_err.c \
	gaa_gl_internal_err.h \
	gaa_policy_evaluator.c \
	gaa_policy_evaluator.h \
	gaa_release.c \
	gaa_utils.c \
	gaa_utils.h \
	globus_gaa.h \
	globus_gaa_utils.c \
	globus_gaa_utils.h \
	gnu_regex.c \
	gnu_regex.h \
	rfc1779.c

noinst_LTLIBRARIES = libglobus_gaa_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES)

AM_CFLAGS = -DDEBUG

libglobus_gaa___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gaa___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)
libglobus_gaa___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_rules
