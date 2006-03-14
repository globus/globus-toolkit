include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata 

Sources= \
    globus_i_xioperf.h \
    globus_xioperf.c  \
    globus_i_xioperf_opts.c


INCLUDES = $(GPT_INCLUDES)
LDADD = $(GPT_PGM_LINKS)

bin_PROGRAMS= \
    globus-xioperf

globus_xioperf_CFLAGS = $(GPT_CFLAGS)
globus_xioperf_SOURCES = $(Sources)
globus_xioperf_LDFLAGS = $(GPT_LDFLAGS)


EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
