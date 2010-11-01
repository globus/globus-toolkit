include $(top_srcdir)/globus_automake_pre

Sources= \
	globus_openssl.c \
	globus_openssl.h

include_HEADERS = \
	globus_openssl.h

lib_LTLIBRARIES = libglobus_openssl.la

INCLUDES = -I.. @GPT_INCLUDES@ 

libglobus_openssl_la_LDFLAGS = @GPT_LDFLAGS@

libglobus_openssl_la_LIBADD = @GPT_LIB_LINKS@

libglobus_openssl_la_SOURCES = $(Sources)

include $(top_srcdir)/globus_automake_post
