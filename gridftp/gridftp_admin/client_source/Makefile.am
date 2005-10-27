include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS=\
	pkgdata

bin_PROGRAMS= \
    get-RP \
    set-RP \
    gridftp-register

get_RP_Sources= get_RP.c
set_RP_Sources= set_RP.c
gridftp_register_Sources= gridftp_register.c

EXTRA_DIST =
INCLUDES = $(GPT_INCLUDES)
LDADD = $(GPT_PGM_LINKS)

get_RP_CFLAGS  = $(GPT_CFLAGS)
get_RP_SOURCES = $(get_RP_Sources)
get_RP_LDFLAGS = $(GPT_LDFLAGS)
set_RP_CFLAGS  = $(GPT_CFLAGS)
set_RP_SOURCES = $(set_RP_Sources)
set_RP_LDFLAGS = $(GPT_LDFLAGS)
gridftp_register_CFLAGS  = $(GPT_CFLAGS)
gridftp_register_SOURCES = $(gridftp_register_Sources)
gridftp_register_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
