include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS=\
    pkgdata

Sources= \
    globus_gridftp_server.c                     \
    globus_gridftp_server_cmd.c                 \
	globus_gridftp_server_attr.c                \
    globus_gridftp_server_pmod_959.c            \
    globus_gridftp_server_pmod_959_cmd.c

flavorinclude_HEADERS = \
    globus_gridftp_server.h

lib_LTLIBRARIES = libglobus_gridftp_server_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES)

libglobus_gridftp_server___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources) 
libglobus_gridftp_server___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_gridftp_server___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	$(GPT_LIB_LINKS)

EXTRA_DIST = \
	version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
