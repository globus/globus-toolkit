include $(top_srcdir)/globus_automake_pre

Sources= \
	globus_openssl.c \
	globus_openssl.h

flavorinclude_HEADERS = \
	globus_openssl.h

lib_LTLIBRARIES = libglobus_openssl_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I.. @GPT_INCLUDES@ 

libglobus_openssl___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@

libglobus_openssl___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@

libglobus_openssl___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

include $(top_srcdir)/globus_automake_post
