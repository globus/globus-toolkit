
include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

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
	wrap.c \
	set_sec_context_opts.c

flavorinclude_HEADERS= \
	globus_gss_assist.h


INCLUDES = $(GPT_INCLUDES)     

lib_LTLIBRARIES = libglobus_gss_assist_$(GLOBUS_FLAVOR_NAME).la
libglobus_gss_assist___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_gss_assist___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_gss_assist___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
