include $(top_srcdir)/globus_automake_pre

Sources = \
	accept_sec_context.c \
	acquire_cred.c \
	compare_name.c \
	delete_sec_context.c \
	display_name.c \
	duplicate_name.c \
	display_status.c \
	export_name.c \
	export_sec_context.c \
	get_mic.c \
	import_name.c \
	import_sec_context.c \
	init_sec_context.c \
	inquire_cred.c \
	inquire_context.c \
	oid_functions.c \
	release_cred.c \
	release_name.c \
	unwrap.c \
	verify_mic.c \
	wrap.c \
	release_buffer.c \
	module.c \
	gssapi_working.c \
	gssapi.h \
	gssapi_openssl.h \
	globus_i_gsi_gss_utils.h \
        globus_i_gsi_gss_utils.c \
        globus_gsi_gss_constants.h \
        globus_gsi_gss_error.c \
	$(Sources_GSS_EXTENSIONS) \
	$(Sources_OPENSSL_INTERNALS)

Sources_GSS_EXTENSIONS = \
	accept_delegation.c \
	import_cred.c \
	export_cred.c \
	init_delegation.c \
	inquire_cred_by_oid.c \
	inquire_sec_context_by_oid.c \
	buffer_set.c \
	set_sec_context_option.c

Sources_OPENSSL_INTERNALS = \
	ssl_locl.h

flavorinclude_HEADERS = \
	gssapi.h


#AM_CFLAGS = -DDEBUG

lib_LTLIBRARIES = libglobus_gssapi_gsi_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I.. $(GPT_INCLUDES)

libglobus_gssapi_gsi___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gssapi_gsi___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)
libglobus_gssapi_gsi___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post