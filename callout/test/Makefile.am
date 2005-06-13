include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata

Data = \
	test.conf

test_DATA = $(Data)

test_PROGRAMS = \
	callout_test \
        callout_chain_test

EXTRA_DIST = $(Data)

INCLUDES = $(GPT_INCLUDES)

LDADD = $(GPT_PGM_LINKS)

callout_test_SOURCES = callout_test.c
callout_test_LDFLAGS = $(GPT_LDFLAGS)

callout_chain_test_SOURCES = callout_chain_test.c
callout_chain_test_LDFLAGS = $(GPT_LDFLAGS)

test_LTLIBRARIES = libtest_$(GLOBUS_FLAVOR_NAME).la \
                   libchaina_test_$(GLOBUS_FLAVOR_NAME).la \
                   libchainb_test_$(GLOBUS_FLAVOR_NAME).la \
                   libchainc_test_$(GLOBUS_FLAVOR_NAME).la

libtest___GLOBUS_FLAVOR_NAME__la_SOURCES = libtest.c
libchaina_test___GLOBUS_FLAVOR_NAME__la_SOURCES = libchaina_test.c
libchainb_test___GLOBUS_FLAVOR_NAME__la_SOURCES = libchainb_test.c
libchainc_test___GLOBUS_FLAVOR_NAME__la_SOURCES = libchainc_test.c

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
