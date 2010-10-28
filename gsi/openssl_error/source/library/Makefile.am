
include $(top_srcdir)/globus_automake_pre

Sources = globus_error_openssl.h \
          globus_error_openssl.c \
          globus_i_error_openssl.h \
          globus_i_error_openssl.c

include_HEADERS = \
          globus_error_openssl.h

lib_LTLIBRARIES = libglobus_openssl_error.la

INCLUDES = -I.. @GPT_INCLUDES@

libglobus_openssl_error_la_LDFLAGS = @GPT_LDFLAGS@

libglobus_openssl_error_la_LIBADD = @GPT_LIB_LINKS@

libglobus_openssl_error_la_SOURCES = $(Sources)

include $(top_srcdir)/globus_automake_post
