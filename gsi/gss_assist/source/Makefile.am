
include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	programs \
	doxygen

Sources= \
	accept.c \
	acquire.c \
	display.c \
	hostname.c \
	globus_gss_assist_constants.h \
	globus_gss_assist_error.c \
	globus_i_gss_assist.h \
	globus_gss_assist_module.c \
	globus_gss_assist.h \
	gridmap.c \
	import_sec_context.c \
	export_sec_context.c \
	init.c \
	tokens_f.c \
	unwrap.c \
	wrap.c \
	set_sec_context_opts.c 

include_HEADERS= \
	globus_gss_assist.h \
        globus_gss_assist_constants.h

INCLUDES = $(GPT_INCLUDES)     

EXTRA_DIST = \
       version.h.in \
       dirt.sh

lib_LTLIBRARIES = libglobus_gss_assist.la
libglobus_gss_assist_la_SOURCES = $(Sources)
libglobus_gss_assist_la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_gss_assist_la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
