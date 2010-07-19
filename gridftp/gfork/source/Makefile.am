include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top


SUBDIRS = \
	pkgdata 

Sources= \
    globus_gfork.h              \
    globus_i_gfork.h            \
    globus_gfork_lib.c          \
    globus_gfork_states.c       \
    globus_gfork_opts.c


INCLUDES = $(GPT_INCLUDES)
LDADD = $(GPT_PGM_LINKS)

flavorinclude_HEADERS = globus_gfork.h

lib_LTLIBRARIES = libglobus_gfork_$(GLOBUS_FLAVOR_NAME).la

libglobus_gfork___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_gfork___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_gfork___GLOBUS_FLAVOR_NAME__la_LIBADD = \
    $(MODULE_LIBS) $(GPT_LIB_LINKS)

sbin_PROGRAMS= \
    gfork

gfork_CFLAGS = $(GPT_CFLAGS)
gfork_SOURCES = globus_gfork_server.c
gfork_LDFLAGS = $(GPT_LDFLAGS)
gfork_LDADD = \
    ./libglobus_gfork_$(GLOBUS_FLAVOR_NAME).la \
    $(GPT_PGM_LINKS)


EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
