include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
        pkgdata

INCLUDES += $(GPT_INCLUDES)

Sources= \
        globus_gridftp_driver_test.c

test_PROGRAMS= \
        globus_gridftp_driver_test

globus_gridftp_driver_test_SOURCES = $(Sources)
globus_gridftp_driver_test_LDFLAGS = $(GPT_LDFLAGS)
globus_gridftp_driver_test_LDADD = $(GPT_PGM_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
