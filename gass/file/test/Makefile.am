include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata

test_PROGRAMS= \
	globus-gass-file-append-fail-test

INCLUDES += $(GPT_INCLUDES)
LDADD = $(GPT_PGM_LINKS)

globus_gass_file_append_fail_test_SOURCES = globus_gass_file_append_fail_test.c
globus_gass_file_append_fail_test_LDFLAGS = $(GPT_LDFLAGS)


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
