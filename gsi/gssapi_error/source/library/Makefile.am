include $(top_srcdir)/globus_automake_pre

Sources= \
	globus_error_gssapi.c \
	globus_i_error_gssapi.c \
	globus_error_gssapi.h \
	globus_i_error_gssapi.h

include_HEADERS = \
	globus_error_gssapi.h

lib_LTLIBRARIES = libglobus_gssapi_error_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = @GPT_INCLUDES@

libglobus_gssapi_error___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_gssapi_error___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

libglobus_gssapi_error___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

include $(top_srcdir)/globus_automake_post
