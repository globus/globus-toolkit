include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

EXTRA_DIST=

SUBDIRS= \
	pkgdata 

simple_Sources=                                \
	globus_gs_simple_test.c

client_Sources=                             \
    globus_ftp_telnet_client.c

server_Sources=                             \
    globus_xio_ftp_server.c

INCLUDES = $(GPT_INCLUDES)

test_PROGRAMS= \
	globus_gs_simple_test       \
	globus_ftp_telnet_client    \
    globus_xio_ftp_server 

globus_gs_simple_test_SOURCES = $(simple_Sources)
globus_gs_simple_test_LDFLAGS = $(GPT_LDFLAGS) -L .
globus_gs_simple_test_LDADD = $(GPT_PGM_LINKS) 

globus_ftp_telnet_client_SOURCES = $(client_Sources)
globus_ftp_telnet_client_LDFLAGS = $(GPT_LDFLAGS) 
globus_ftp_telnet_client_LDADD = $(GPT_PGM_LINKS) 

globus_xio_ftp_server_SOURCES = $(server_Sources)
globus_xio_ftp_server_LDFLAGS = $(GPT_LDFLAGS) -L .
globus_xio_ftp_server_LDADD = $(GPT_PGM_LINKS) 

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
