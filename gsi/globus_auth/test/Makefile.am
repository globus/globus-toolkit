include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	ex.c \
	gaa_utils.h \
	gss_client.c \
	gss_misc.h \
	gaa_utils.c \
	gaatest.c \
	gss_misc.c \
	gss_server.c

INCLUDES += $(GPT_INCLUDES)

test_PROGRAMS = \
	gss-server \
	gss-client

gss_server_SOURCES = \
	gss_server.c \
	gss_misc.c \
	gss_misc.h \
	gaa_utils.c \
	gaa_utils.h

gss_server_LDFLAGS = $(GPT_LDFLAGS)

gss_server_LDADD = $(GPT_PGM_LINKS)

gss_client_SOURCES = \
	gss_client.c \
	gss_misc.c \
	gss_misc.h

gss_client_LDFLAGS = $(GPT_LDFLAGS)

gss_client_LDADD = $(GPT_PGM_LINKS)


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
