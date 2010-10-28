
include $(top_srcdir)/globus_automake_pre

Sources= \
	globus_gsi_credential.h \
	globus_gsi_credential.c \
	globus_i_gsi_credential.h \
	globus_gsi_cred_handle.c \
	globus_gsi_cred_handle_attrs.c \
	globus_gsi_cred_constants.h \
	globus_gsi_cred_error.c 

include_HEADERS= \
	globus_gsi_credential.h \
	globus_gsi_cred_constants.h

lib_LTLIBRARIES = libglobus_gsi_credential.la

INCLUDES = -I.. @GPT_INCLUDES@

libglobus_gsi_credential_la_SOURCES = $(Sources)

libglobus_gsi_credential_la_LIBADD = @GPT_LIB_LINKS@

libglobus_gsi_credential_la_LDFLAGS = @GPT_LDFLAGS@

include $(top_srcdir)/globus_automake_post
