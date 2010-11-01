
include $(top_srcdir)/globus_automake_pre

SUBDIRS = pkgdata

Sources= globus_usage.c

include_HEADERS = globus_usage.h


lib_LTLIBRARIES = libglobus_usage.la 

INCLUDES = @GPT_INCLUDES@

libglobus_usage_la_LIBADD = @GPT_LIB_LINKS@

libglobus_usage_la_SOURCES = $(Sources)
libglobus_usage_la_LDFLAGS = @GPT_LDFLAGS@

include $(top_srcdir)/globus_automake_post
