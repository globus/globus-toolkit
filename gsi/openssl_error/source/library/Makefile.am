
include $(top_srcdir)/globus_automake_pre

Sources = globus_error_openssl.h \
          globus_error_openssl.c \
          globus_i_error_openssl.h \
          globus_i_error_openssl.c

flavorinclude_HEADERS = \
          globus_error_openssl.h

lib_LTLIBRARIES = libglobus_openssl_error_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I.. @GPT_INCLUDES@

libglobus_openssl_error___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@

libglobus_openssl_error___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@

libglobus_openssl_error___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

include $(top_srcdir)/globus_automake_post