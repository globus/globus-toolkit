
include $(top_srcdir)/globus_automake_pre

Sources= \
	globus_callout.h \
	globus_i_callout.h \
	globus_callout.c \
	globus_callout_constants.h \
	globus_callout_error.c 

flavorinclude_HEADERS= \
	globus_callout.h \
	globus_callout_constants.h

lib_LTLIBRARIES = libglobus_callout_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I.. @GPT_INCLUDES@ -I$(top_srcdir)/library/oldgaa

libglobus_callout___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_callout___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@ 

libglobus_callout___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@

include $(top_srcdir)/globus_automake_post
