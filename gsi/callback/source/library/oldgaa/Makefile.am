include $(top_srcdir)/globus_automake_pre

Sources= \
	oldgaa_alloc.c \
	oldgaa_api.c \
	oldgaa_gl_internal_err.c \
	oldgaa_gl_internal_err.h \
	oldgaa_policy_evaluator.c \
	oldgaa_policy_evaluator.h \
	oldgaa_release.c \
	oldgaa_utils.c \
	oldgaa_utils.h \
	globus_oldgaa.h \
	globus_oldgaa_utils.c \
	globus_oldgaa_utils.h \
	rfc1779.c \
	rfc1779.h

EXTRA_DIST= \
        config.h.in

lib_LTLIBRARIES = libglobus_oldgaa.la

INCLUDES = $(GPT_INCLUDES) -I.

#AM_CFLAGS = -DDEBUG

libglobus_oldgaa_la_SOURCES = $(Sources)

libglobus_oldgaa_la_LIBADD = $(GPT_LIB_LINKS)
libglobus_oldgaa_la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post
