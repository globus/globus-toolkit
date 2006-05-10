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
	globus-gram-protocol-pack-test.pl

Data = \
	dc31a685.0 \
	dc31a685.signing_policy \
	testcred.pem

pkgtest_SCRIPTS=$(Scripts) globus-gram-protocol-run-tests.pl

pkgtest_DATA=$(Data)

pkgtest_PROGRAMS= \
	globus-gram-protocol-allow-attach-test \
	globus-gram-protocol-delegation-test \
        globus-gram-protocol-error-test \
	globus-gram-protocol-io-test \
	globus-gram-protocol-pack-test

EXTRA_DIST=$(Scripts) globus-gram-protocol-run-tests.pl.in $(Data)

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

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
