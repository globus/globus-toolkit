include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata 

Sources= \
    globus_hostname_lookup.c


INCLUDES = $(GPT_INCLUDES)
LDADD = $(GPT_PGM_LINKS)

bin_PROGRAMS= \
    globus-hostname-lookup

globus_hostname_lookup_CFLAGS = $(GPT_CFLAGS)
globus_hostname_lookup_SOURCES = $(Sources)
globus_hostname_lookup_LDFLAGS = $(GPT_LDFLAGS)


EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
