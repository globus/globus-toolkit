include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	gaa_test_with_assertion_file.c \
	gaa_test_utils.c

INCLUDES += $(GPT_INCLUDES)

gaa_test_with_assertion_file_SOURCES = gaa_test_with_assertion_file.c gaa_test_utils.c
gaa_test_with_assertion_file_LDFLAGS = $(GPT_LDFLAGS)
gaa_test_with_assertion_file_LDADD = $(GPT_PGM_LINKS)

test_PROGRAMS=gaa_test_with_assertion_file

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
