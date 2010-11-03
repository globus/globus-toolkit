
include $(top_srcdir)/globus_automake_pre

Sources= \
	globus_callout.h \
	globus_i_callout.h \
	globus_callout.c \
	globus_callout_constants.h \
	globus_callout_error.c 

include_HEADERS= \
	globus_callout.h \
	globus_callout_constants.h

lib_LTLIBRARIES = libglobus_callout.la

INCLUDES = -I.. @GPT_INCLUDES@ -I$(top_srcdir)/library/oldgaa

libglobus_callout_la_SOURCES = $(Sources)

libglobus_callout_la_LIBADD = @GPT_LIB_LINKS@ 

libglobus_callout_la_LDFLAGS = @GPT_LDFLAGS@

include $(top_srcdir)/globus_automake_post
