include $(top_srcdir)/globus_automake_pre

Sources = \
	accept_sec_context.c \
	acquire_cred.c \
	compare_name.c \
	delete_sec_context.c \
	display_name.c \
	display_status.c \
	export_name.c \
	export_sec_context.c \
	get_mic.c \
	gsserr.c \
	gssutils.c \
	gssutils.h \
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
	gssapi_working.c \
	gssapi.h \
	gssapi_ssleay.h \
	$(Sources_GSS_EXTENSIONS)

Sources_GSS_EXTENSIONS = \
	module.c \
	accept_delegation.c \
	import_cred.c \
	export_cred.c \
	init_delegation.c \
	inquire_cred_by_oid.c \
	inquire_sec_context_by_oid.c \
	buffer_set.c \
	policy_sign.c \
	policy_verify.c \
	set_sec_context_option.c \
	set_group.c \
	get_group.c

flavorinclude_HEADERS = \
	gssapi.h \
	globus_gssapi_config.h

#AM_CFLAGS = -DDEBUG

lib_LTLIBRARIES = libglobus_gssapi_gsi_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I.. $(GPT_INCLUDES)

libglobus_gssapi_gsi___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gssapi_gsi___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)
libglobus_gssapi_gsi___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post




