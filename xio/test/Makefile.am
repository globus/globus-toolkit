include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata 

Sources=                                \
	test_common.c                       \
	framework_test.c                    \
	timeout_test.c                      \
    close_barrier_test.c                \
    cancel_test.c                       \
    attr_test.c                         \
    read_barrier_test.c

INCLUDES += $(GPT_INCLUDES)

test_PROGRAMS= \
	framework_test

framework_test_SOURCES = $(Sources)
framework_test_LDFLAGS = $(GPT_LDFLAGS)
framework_test_LDADD = $(GPT_PGM_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
