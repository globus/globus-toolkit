include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata

Scripts = globus-gram-client-activate-test.pl \
          globus-gram-client-callback-contact-test.pl \
          globus-gram-client-cancel-test.pl \
          globus-gram-client-ping-test.pl \
          globus-gram-client-register-test.pl \
	  globus-gram-client-register-callback-test.pl \
          globus-gram-client-run-tests.pl
test_SCRIPTS=$(Scripts)
test_PROGRAMS= \
	globus-gram-client-activate-test \
	globus-gram-client-callback-contact-test \
	globus-gram-client-test \
	globus-gram-client-cancel-test \
	globus-gram-client-ping-test \
	globus-gram-client-register-callback-test \
	globus-gram-client-register-test
EXTRA_DIST=$(test_SCRIPTS)
INCLUDES += $(GPT_INCLUDES)

LDADD = $(GPT_PGM_LINKS)
globus_gram_client_register_callback_test_SOURCES = globus_gram_client_register_callback_test.c
globus_gram_client_register_callback_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_activate_test_SOURCES = globus_gram_client_activate_test.c
globus_gram_client_activate_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_callback_contact_test_SOURCES = globus_gram_client_callback_contact_test.c
globus_gram_client_callback_contact_test_LDFLAGS = $(GPT_LDFLAGS)

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
