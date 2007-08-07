include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata \
	doxygen

INCLUDES = $(GPT_INCLUDES)

master_Sources = gfork_test_master.c
worker_Sources = gfork_test_worker.c

bin_PROGRAMS= \
    gfork-test-master \
    gfork-test-worker

gfork_test_master_CFLAGS = $(GPT_CFLAGS)
gfork_test_master_SOURCES = $(master_Sources)
gfork_test_master_LDFLAGS = $(GPT_LDFLAGS)
gfork_test_master_LDADD = $(GPT_PGM_LINKS)

gfork_test_worker_CFLAGS = $(GPT_CFLAGS)
gfork_test_worker_SOURCES = $(worker_Sources)
gfork_test_worker_LDFLAGS = $(GPT_LDFLAGS)
gfork_test_worker_LDADD = $(GPT_PGM_LINKS)


EXTRA_DIST = version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
