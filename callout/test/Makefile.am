include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata

Data = \
	test.conf

test_DATA = $(Data)

test_PROGRAMS = \
	callout_test

EXTRA_DIST = $(Data)

INCLUDES += $(GPT_INCLUDES)

LDADD = $(GPT_PGM_LINKS)

callout_test_SOURCES = callout_test.c
callout_test_LDFLAGS = $(GPT_LDFLAGS)

test_LTLIBRARIES = libtest_$(GLOBUS_FLAVOR_NAME).la

libtest___GLOBUS_FLAVOR_NAME__la_SOURCES = libtest.c

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
