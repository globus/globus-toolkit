include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata

test_server_Sources=     \
	test_server.c

gftp_Sources=       \
	gftp.c

data_test_Sources= \
        test_common.c \
        test_common.h \
	data_test.c


INCLUDES += $(GPT_INCLUDES)

test_PROGRAMS= \
	gftp \
	test_server \
	data_test 

gftp_SOURCES = $(gftp_Sources)
gftp_LDFLAGS = $(GPT_LDFLAGS)
gftp_LDADD = $(GPT_PGM_LINKS)

data_test_SOURCES = $(data_test_Sources)
data_test_LDFLAGS = $(GPT_LDFLAGS)
data_test_LDADD = $(GPT_PGM_LINKS)

test_server_SOURCES = $(test_server_Sources)
test_server_LDFLAGS = $(GPT_LDFLAGS)
test_server_LDADD = $(GPT_PGM_LINKS)


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
