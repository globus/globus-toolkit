include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata 

simple_Sources=                                \
	globus_gs_simple_test.c 

test_Sources=\
    globus_gsc_test_common.c    \
    globus_gsc_test_common.h    \
    globus_gsc_test_auth.c

INCLUDES += $(GPT_INCLUDES)

test_PROGRAMS= \
	globus_gs_simple_test   \
    globus_gsc_test_auth

globus_gs_simple_test_SOURCES = $(simple_Sources)
globus_gs_simple_test_LDFLAGS = $(GPT_LDFLAGS) -L .
globus_gs_simple_test_LDADD = $(GPT_PGM_LINKS) 

globus_gsc_test_auth_SOURCES = $(test_Sources)
globus_gsc_test_auth_LDFLAGS = $(GPT_LDFLAGS) -L .
globus_gsc_test_auth_LDADD = $(GPT_PGM_LINKS) 

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
