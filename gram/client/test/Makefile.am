include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata

test_PROGRAMS= \
	globus-gram-client-test

INCLUDES += $(GPT_INCLUDES)

LDADD = $(GPT_PGM_LINKS)
globus_gram_client_test_SOURCES = globus_gram_client_test.c

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
