include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata 

simple_Sources=                                \
	globus_gs_simple_test.c 

INCLUDES += $(GPT_INCLUDES)

test_PROGRAMS= \
	globus_gs_simple_test 

globus_gs_simple_test_SOURCES = $(simple_Sources)
globus_gs_simple_test_LDFLAGS = $(GPT_LDFLAGS) -L .
globus_gs_simple_test_LDADD = $(GPT_PGM_LINKS) 

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
