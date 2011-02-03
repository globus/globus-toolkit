include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata

Sources= globus_usage.c

include_HEADERS = globus_usage.h

lib_LTLIBRARIES = libglobus_usage.la 

INCLUDES = @GPT_INCLUDES@

libglobus_usage_la_LIBADD = @GPT_LIB_LINKS@

libglobus_usage_la_SOURCES = $(Sources)
libglobus_usage_la_LDFLAGS = @GPT_LDFLAGS@

doc_DATA = GLOBUS_LICENSE

EXTRA_DIST = globus-usage.spec $(doc_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
