include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS=\
	pkgdata

test_PROGRAMS= \
	get-RP \
	set-RP \
	gridftp-register

EXTRA_DIST =
INCLUDES = $(GPT_INCLUDES)
LDADD = $(GPT_PGM_LINKS)

get_RP_SOURCES = get_RP.c
get_RP_LDFLAGS = $(GPT_LDFLAGS)
set_RP_SOURCES = get_RP.c
set_RP_LDFLAGS = $(GPT_LDFLAGS)
gridftp_register_SOURCES = gridftp_register.c
gridftp_register_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
