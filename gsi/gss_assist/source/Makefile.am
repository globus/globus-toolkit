include $(top_srcdir)/globus_automake_config
include $(top_srcdir)/globus_automake_targets

SUBDIRS = pkgdata

Sources= \
	accept.c \
	acconfig.h \
	acquire.c \
	display.c \
	globus_gss_assist.h \
	gridmap.c \
	import_sec_context.c \
	init.c \
	tokens_f.c \
	unwrap.c \
	wrap.c

include_HEADERS= \
	globus_gss_assist.h


INCLUDES = $(GPT_INCLUDES)     

lib_LTLIBRARIES = libglobus_gss_assist_$(GLOBUS_FLAVOR_NAME).la
libglobus_gss_assist___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
include $(top_srcdir)/globus_automake_rules
include $(top_srcdir)/globus_automake_top_rules
