include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS=\
	pkgdata

test_PROGRAMS= \
	globus-xio-client \
	globus-xio-email \
	globus-xio-example \
	globus-xio-server \
	globus-xio-udp-echo \
	globus-xio-udt-file \
	globus-xio-mode-e-file \
	globus-xio-ordering-file \
	globus-xio-async-copy \
	globus-xio-bidi-client


EXTRA_DIST =
INCLUDES = $(GPT_INCLUDES)
LDADD = $(GPT_PGM_LINKS)

globus_xio_client_SOURCES = globus_xio_client.c
globus_xio_client_LDFLAGS = $(GPT_LDFLAGS)
globus_xio_email_SOURCES = globus_xio_email.c
globus_xio_email_LDFLAGS = $(GPT_LDFLAGS)
globus_xio_example_SOURCES = globus_xio_example.c
globus_xio_example_LDFLAGS = $(GPT_LDFLAGS)
globus_xio_server_SOURCES = globus_xio_server.c
globus_xio_server_LDFLAGS = $(GPT_LDFLAGS)
globus_xio_udp_echo_SOURCES = globus_xio_udp_echo.c
globus_xio_udp_echo_LDFLAGS = $(GPT_LDFLAGS)
globus_xio_udt_file_SOURCES = globus_xio_udt_file.c
globus_xio_udt_file_LDFLAGS = $(GPT_LDFLAGS)
globus_xio_mode_e_file_SOURCES = globus_xio_mode_e_file.c
globus_xio_mode_e_file_LDFLAGS = $(GPT_LDFLAGS)
globus_xio_ordering_file_SOURCES = globus_xio_ordering_file.c
globus_xio_ordering_file_LDFLAGS = $(GPT_LDFLAGS)
globus_xio_async_copy_SOURCES = globus_xio_async_copy.c
globus_xio_async_copy_LDFLAGS = $(GPT_LDFLAGS)
globus_xio_bidi_client_SOURCES = globus_xio_bidi_client.c
globus_xio_bidi_client_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
