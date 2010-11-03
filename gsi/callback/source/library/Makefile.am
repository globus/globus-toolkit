
include $(top_srcdir)/globus_automake_pre

SUBDIRS = oldgaa

Sources= \
	globus_gsi_callback.h \
	globus_i_gsi_callback.h \
	globus_gsi_callback.c \
	globus_gsi_callback_constants.h \
	globus_gsi_callback_error.c \
	globus_gsi_callback_data.c

include_HEADERS= \
	globus_gsi_callback.h \
	globus_gsi_callback_constants.h

lib_LTLIBRARIES = libglobus_gsi_callback.la

INCLUDES = -I.. @GPT_INCLUDES@ -I$(top_srcdir)/library/oldgaa

libglobus_gsi_callback_la_SOURCES = $(Sources)

libglobus_gsi_callback_la_LIBADD = ./oldgaa/libglobus_oldgaa.la  @GPT_LIB_LINKS@
libglobus_gsi_callback_la_LDFLAGS = @GPT_LDFLAGS@

include $(top_srcdir)/globus_automake_post
