include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

gftp_Sources= \
	gftp.c

data_test_Sources= \
        test_common.c \
        test_common.h \
	data_test.c


INCLUDES += $(GPT_INCLUDES)

test_PROGRAMS= \
	gftp \
	data_test 

gftp_SOURCES = $(gftp_Sources)

gftp_LDFLAGS = $(GPT_LDFLAGS)

gftp_LDADD = $(GPT_PGM_LINKS)

data_test_SOURCES = $(data_test_Sources)

data_test_LDFLAGS = $(GPT_LDFLAGS)

data_test_LDADD = $(GPT_PGM_LINKS)


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
