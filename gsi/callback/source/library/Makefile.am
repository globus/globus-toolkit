
include $(top_srcdir)/globus_automake_pre

SUBDIRS = oldgaa

Sources= \
	globus_gsi_callback.h \
	globus_i_gsi_callback.h \
	globus_gsi_callback.c \
	globus_gsi_callback_constants.h \
	globus_gsi_callback_error.c \
	globus_gsi_callback_data.c

flavorinclude_HEADERS= \
	globus_gsi_callback.h \
	globus_gsi_callback_constants.h

lib_LTLIBRARIES = libglobus_gsi_callback_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I.. @GPT_INCLUDES@ -I$(top_srcdir)/library/oldgaa

libglobus_gsi_callback___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gsi_callback___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@ -lglobus_oldgaa_$(GLOBUS_FLAVOR_NAME)

libglobus_gsi_callback___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@ -L./oldgaa/

include $(top_srcdir)/globus_automake_post
