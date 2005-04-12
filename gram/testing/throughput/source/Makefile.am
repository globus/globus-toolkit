include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

# SUBDIRS is an automake macro which contains
# the list of subdirectories that have Makefile.am's
SUBDIRS = \
	pkgdata 

Sources = \
	globus_i_args.c \
	globus_i_stats.c \
	prews_gram_throughput_test.c

noinst_HEADERS = \
	globus_i_prews_gram_throughput_test.h

INCLUDES = $(GPT_INCLUDES)

# EXTRA_DIST is used to include files in
# a source distribution that automake fails to detect.
EXTRA_DIST = \
	version.h.in

bin_PROGRAMS = prews-gram-throughput-test

prews_gram_throughput_test_SOURCES = $(Sources)
prews_gram_throughput_test_CFLAGS = $(GPT_CFLAGS)
prews_gram_throughput_test_LDFLAGS = $(GPT_LDFLAGS)
prews_gram_throughput_test_LDADD = $(GPT_PGM_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

