include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata 

Sources= \
    globus_i_gwtftp.h \
    globus_i_gwtftp.c  \
    globus_i_gwtftp_client.c \
    globus_i_gwtftp_server.c \
    globus_i_gwtftp_cmd.c  \
    globus_i_gwtftp_opts.c


INCLUDES = $(GPT_INCLUDES)
LDADD = $(GPT_PGM_LINKS)

bin_PROGRAMS= \
    gwtftp

gwtftp_CFLAGS = $(GPT_CFLAGS)
gwtftp_SOURCES = $(Sources)
gwtftp_LDFLAGS = $(GPT_LDFLAGS)


EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
