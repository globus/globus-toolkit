include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS=\
    pkgdata

Sources= \
    globus_gridftp_server_control.c                     \
	globus_gridftp_server_control_attr.c                \
    globus_gridftp_server_control_accessors.c        \
    globus_gridftp_server_control_commands.c

flavorinclude_HEADERS =                         \
    globus_i_gridftp_server_control.h           \
    globus_gridftp_server_control.h

lib_LTLIBRARIES = libglobus_gridftp_server_control_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES)

libglobus_gridftp_server_control___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources) 
libglobus_gridftp_server_control___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
    $(GPT_LDFLAGS)
libglobus_gridftp_server_control___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	$(GPT_LIB_LINKS)

EXTRA_DIST = \
	version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
