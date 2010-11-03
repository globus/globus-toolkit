include $(top_srcdir)/globus_automake_pre

Sources= \
	globus_error_gssapi.c \
	globus_i_error_gssapi.c \
	globus_error_gssapi.h \
	globus_i_error_gssapi.h

include_HEADERS = \
	globus_error_gssapi.h

lib_LTLIBRARIES = libglobus_gssapi_error.la

INCLUDES = @GPT_INCLUDES@

libglobus_gssapi_error_la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_gssapi_error_la_LIBADD = $(GPT_LIB_LINKS)

libglobus_gssapi_error_la_SOURCES = $(Sources)

include $(top_srcdir)/globus_automake_post
