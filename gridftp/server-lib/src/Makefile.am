include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS=\
    pkgdata

Sources= \
    globus_i_gridftp_server_control.h                   \
    globus_gridftp_server_control.c                     \
	globus_gridftp_server_control_attr.c                \
    globus_gridftp_server_control_accessors.c           \
    globus_gridftp_server_control_events.c              \
    globus_gridftp_server_control_commands.c            \
    globus_xio_gssapi_ftp.c

include_HEADERS =                         \
    globus_gridftp_server_control.h             \
    globus_xio_gssapi_ftp.h

lib_LTLIBRARIES = libglobus_gridftp_server_control.la

doc_DATA = GLOBUS_LICENSE

INCLUDES = $(GPT_INCLUDES)

libglobus_gridftp_server_control_la_SOURCES = $(Sources) 
libglobus_gridftp_server_control_la_LDFLAGS = \
    $(GPT_LDFLAGS)
libglobus_gridftp_server_control_la_LIBADD = \
	$(GPT_LIB_LINKS)

EXTRA_DIST = version.h.in globus-gridftp-server-control.spec $(doc_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
