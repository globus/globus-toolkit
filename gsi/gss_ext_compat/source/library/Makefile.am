
include $(top_srcdir)/globus_automake_pre

Sources= \
        globus_gss_ext_compat.h \
        gss_ext_compat.c

flavorinclude_HEADERS= \
        globus_gss_ext_compat.h


lib_LTLIBRARIES = libglobus_gss_ext_compat.la

INCLUDES = $(GPT_INCLUDES)

libglobus_gss_ext_compat_la_SOURCES = $(Sources)
libglobus_gss_ext_compat_la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_gss_ext_compat_la_LIBADD  = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
