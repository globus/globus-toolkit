noinst_PROGRAMS= globus-gridftp-server-embedded
	
AM_CPPFLAGS = $(GPT_INCLUDES)

globus_gridftp_server_embedded_SOURCES = globus_gridftp_server_embedded.c
globus_gridftp_server_embedded_LDFLAGS = $(GPT_LDFLAGS)
globus_gridftp_server_embedded_LDADD = \
        $(top_builddir)/libglobus_gridftp_server.la \
        $(GPT_PGM_LINKS)

EXTRA_DIST = dirt.sh
