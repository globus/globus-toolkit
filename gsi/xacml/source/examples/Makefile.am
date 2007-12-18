AUTOMAKE_OPTIONS=foreign

if ENABLE_GSSAPI
GSSAPI_IO_LIB = libxacml_gss_io.la
endif

lib_LTLIBRARIES = $(GSSAPI_IO_LIB)

CPPFLAGS=$(GSSAPI_CPPFLAGS)
CFLAGS=$(GSSAPI_CFLAGS) -I$(top_srcdir)
LDADD=$(GSSAPI_LDFLAGS)

libxacml_gss_io_la_SOURCES = xacml_gss_io.c xacml_gss_io.h
libxacml_gss_io_la_LDFLAGS = -module
libxacml_gss_io_la_LIBADD = $(GSSAPI_LIBS)
