include $(top_srcdir)/globus_automake_pre

Sources= \
	globus_error_gssapi.c \
	globus_i_error_gssapi.c \
	globus_error_gssapi.h \
	globus_i_error_gssapi.h

flavorinclude_HEADERS = \
	globus_error_gssapi.h

lib_LTLIBRARIES = libgssapi_error_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = @GPT_INCLUDES@

libgssapi_error___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libgssapi_error___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

libgssapi_error___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

include $(top_srcdir)/globus_automake_post
