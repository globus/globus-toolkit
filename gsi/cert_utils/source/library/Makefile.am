
include $(top_srcdir)/globus_automake_pre

Sources= \
	globus_gsi_cert_utils.h \
	globus_gsi_cert_utils_constants.h \
	globus_i_gsi_cert_utils.h \
	globus_gsi_cert_utils.c \
	globus_gsi_cert_utils_error.c

flavorinclude_HEADERS= \
	globus_gsi_cert_utils.h \
	globus_gsi_cert_utils_constants.h

lib_LTLIBRARIES = libglobus_gsi_cert_utils_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I.. @GPT_INCLUDES@

libglobus_gsi_cert_utils___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gsi_cert_utils___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@

libglobus_gsi_cert_utils___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@

include $(top_srcdir)/globus_automake_post
