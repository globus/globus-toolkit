include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

Sources = \
	gaa_test_with_assertion_file.c \
	gaa_test_utils.c \
	gaa_test_utils.h

EXTRA_DIST=

INCLUDES = $(GPT_INCLUDES)

gaa_test_with_assertion_file_SOURCES = gaa_test_with_assertion_file.c gaa_test_utils.c
gaa_test_with_assertion_file_LDFLAGS = $(GPT_LDFLAGS)
gaa_test_with_assertion_file_LDADD = $(GPT_PGM_LINKS)

gaa_cred_test_SOURCES =	gaa_cred_test.c \
			gssapi_test_utils.c \
			gssapi_test_utils.h \
			gaa_test_utils.c \
			gaa_test_utils.h

gaa_cred_test_LDFLAGS = $(GPT_LDFLAGS)

gaa_cred_test_LDADD = $(GPT_PGM_LINKS)


test_PROGRAMS=gaa_test_with_assertion_file gaa_cred_test

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
