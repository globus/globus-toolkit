
include $(top_srcdir)/globus_automake_pre

SUBDIRS = pkgdata

Sources= globus_usage.c

flavorinclude_HEADERS = globus_usage.h


lib_LTLIBRARIES = libglobus_usage_$(GLOBUS_FLAVOR_NAME).la 

INCLUDES = @GPT_INCLUDES@

libglobus_usage___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@

libglobus_usage___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_usage___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@

include $(top_srcdir)/globus_automake_post
