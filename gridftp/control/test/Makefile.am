include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen


Control_Test_Sources= \
	abort_test.c \
	async_control_test.c \
	connect_disconnect_test.c \
	eb_simple_data_test.c \
	globus_ftp_control_test.c \
	outstanding_io_test.c \
	pending_command_test.c \
	data_commands_fail_test.c \
	simple_control_test.c \
	simple_data_test.c \
	simple_dir_test.c \
	test_common.c \
	globus_ftp_control_test.h \
	test_common.h

gftp_Sources= \
	gftp.c

wu_test_Sources= \
	wu_test.c \
	connect_disconnect_test.c \
	test_common.c \
	test_common.h

put_test_Sources= \
	put_test.c \
	connect_disconnect_test.c \
	test_common.c \
	test_common.h


third_party_test_Sources= \
	third_party_test.c \
	connect_disconnect_test.c \
	test_common.c \
	test_common.h

misc_Sources= \
	control_fail_test.c \
	data_test.c \
	dir_command_test.c \
	get_lingering_close.c \
	pipe_test.c



INCLUDES += $(GPT_INCLUDES)

test_PROGRAMS= \
	globus_ftp_control_test \
	gftp \
	wu_test \
	third_party_test \
	put_test 

globus_ftp_control_test_SOURCES = $(Control_Test_Sources)  

globus_ftp_control_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_control_test_LDADD = $(GPT_PGM_LINKS)



gftp_SOURCES = $(gftp_Sources)

gftp_LDFLAGS = $(GPT_LDFLAGS)

gftp_LDADD = $(GPT_PGM_LINKS)



wu_test_SOURCES = $(wu_test_Sources)

wu_test_LDFLAGS = $(GPT_LDFLAGS)

wu_test_LDADD = $(GPT_PGM_LINKS)



third_party_test_SOURCES = $(third_party_test_Sources)

third_party_test_LDFLAGS = $(GPT_LDFLAGS)

third_party_test_LDADD = $(GPT_PGM_LINKS)



put_test_SOURCES = $(put_test_Sources)

put_test_LDFLAGS = $(GPT_LDFLAGS)

put_test_LDADD = $(GPT_PGM_LINKS)




include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

