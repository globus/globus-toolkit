
include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources= \
	globus_error_openssl.h \
	globus_error_openssl.c

flavorinclude_HEADERS= \
	globus_error_openssl.h

lib_LTLIBRARIES = libglobus_gsi_openssl_error_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES)

libglobus_gsi_openssl_error___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gsi_openssl_error___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

libglobus_gsi_openssl_error___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top





