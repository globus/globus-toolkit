include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata

test_PROGRAMS= \
	globus-gram-client-test \
	globus-gram-client-cancel-test \
	globus-gram-client-ping-test \
	globus-gram-client-register-test

INCLUDES += $(GPT_INCLUDES)

LDADD = $(GPT_PGM_LINKS)
globus_gram_client_test_SOURCES = globus_gram_client_test.c
globus_gram_client_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_ping_test_SOURCES = globus_gram_client_ping_test.c
globus_gram_client_ping_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_cancel_test_SOURCES = globus_gram_client_cancel_test.c
globus_gram_client_cancel_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_register_test_SOURCES = globus_gram_client_register_test.c
globus_gram_client_register_test_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
