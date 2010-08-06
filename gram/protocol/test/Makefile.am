include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata

pkgtestdir = $(GLOBUS_LOCATION)/test/$(PACKAGE)

Scripts = \
	TESTS.pl \
	globus-gram-protocol-allow-attach-test.pl \
	globus-gram-protocol-error-test.pl \
	globus-gram-protocol-io-test.pl \
	globus-gram-protocol-pack-test.pl \
        create-extensions-test.pl \
        pack-with-extensions-test.pl \
        unpack-message-test.pl \
        unpack-with-extensions-test.pl \
        unpack-job-request-reply-with-extensions-test.pl \
        unpack-status-reply-with-extensions-test.pl


pkgtest_SCRIPTS=$(Scripts) globus-gram-protocol-run-tests.pl

pkgtest_PROGRAMS= \
	globus-gram-protocol-allow-attach-test \
	globus-gram-protocol-delegation-test \
        globus-gram-protocol-error-test \
	globus-gram-protocol-io-test \
	globus-gram-protocol-pack-test \
        create-extensions-test \
        pack-with-extensions-test \
        unpack-message-test \
        unpack-with-extensions-test \
        unpack-job-request-reply-with-extensions-test \
        unpack-status-reply-with-extensions-test

EXTRA_DIST=$(Scripts) globus-gram-protocol-run-tests.pl.in
CLEANFILES = globus-gram-protocol-run-tests.pl

INCLUDES = $(GPT_INCLUDES)

LDADD = $(GPT_PGM_LINKS)
globus_gram_protocol_pack_test_SOURCES = globus_gram_protocol_pack_test.c
globus_gram_protocol_pack_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_protocol_io_test_SOURCES = globus_gram_protocol_io_test.c
globus_gram_protocol_io_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_protocol_allow_attach_test_SOURCES = globus_gram_protocol_allow_attach_test.c
globus_gram_protocol_allow_attach_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_protocol_error_test_SOURCES = globus_gram_protocol_error_test.c
globus_gram_protocol_error_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_protocol_delegation_test_SOURCES = globus_gram_protocol_delegation_test.c
globus_gram_protocol_delegation_test_LDFLAGS = $(GPT_LDFLAGS)

unpack_job_request_reply_with_extensions_test_SOURCES = \
        unpack_job_request_reply_with_extensions_test.c
unpack_job_request_reply_with_extensions_test_LDFLAGS = $(GPT_LDFLAGS)

unpack_status_reply_with_extensions_test_SOURCES = unpack_status_reply_with_extensions_test.c
unpack_status_reply_with_extensions_test_LDFLAGS = $(GPT_LDFLAGS)

create_extensions_test_SOURCES = create_extensions_test.c
create_extensions_test_LDFLAGS = $(GPT_LDFLAGS)

pack_with_extensions_test_SOURCES = pack_with_extensions_test.c
pack_with_extensions_test_LDFLAGS = $(GPT_LDFLAGS)

unpack_message_test_SOURCES = unpack_message_test.c
unpack_message_test_LDFLAGS = $(GPT_LDFLAGS)

unpack_with_extensions_test_SOURCES = unpack_with_extensions_test.c
unpack_with_extensions_test_LDFLAGS = $(GPT_LDFLAGS)

globus-gram-protocol-run-tests.pl: $(srcdir)/globus-gram-protocol-run-tests.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
