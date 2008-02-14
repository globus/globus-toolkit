include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	drivers \
	pkgdata 

Sources=                                \
	test_common.h                   \
	test_common.c                   \
	driver_stack.c                  \
	blocking_dd_test.c              \
	unload_test.c                   \
	framework_test.c                \
	space_test.c                    \
	timeout_test.c                  \
	close_barrier_test.c            \
	close_barrier2_test.c           \
	close_cancel_test.c             \
	cancel_test.c                   \
	server2_test.c                  \
	attr_test.c                     \
	block_barrier_test.c            \
	read_barrier_test.c

INCLUDES = -Idrivers $(GPT_INCLUDES)

test_PROGRAMS=                          \
	framework_test			\
	http_header_test		\
	http_post_test			\
	http_put_test			\
	http_get_test			\
	http_pingpong_test		\
	http_timeout_test 		\
    handle_create_from_url_test \
	http_throughput_test

Data =                                  \
	headers				\
	multi-line-header		\
	long-headers			\
	multi-headers			\
	large-file

pkgdata_DATA =$(Data)

Scripts = 				\
	basic-test.pl                   \
	close-barrier-test.pl           \
	close-cancel-test.pl            \
	failure-test.pl                 \
	read-barrier-test.pl            \
	timeout-test.pl                 \
	cancel-test.pl                  \
	random-test.pl                  \
	server-test.pl                  \
	verify-test.pl                  \
	attr-test.pl                    \
	space-test.pl                   \
	server2-test.pl                 \
	block-barrier-test.pl           \
	stack-test.pl                   \
	unload-test.pl                  \
	http-get-test.pl		\
	http-header-test.pl		\
	http-post-test.pl		\
	http-put-test.pl		\
        http-pingpong-test.pl		\
	http-timeout-test.pl		\
	http-throughput-test.pl		\
	test-common.pl                  \
	run-http-tests.pl               \
	run-xio-tests.pl                \
	run-all-tests.pl                \
	TESTS.pl

test_SCRIPTS = $(Scripts)

EXTRA_DIST = $(Scripts) $(Data) 

LDADD = $(GPT_PGM_LINKS)

framework_test_SOURCES = $(Sources)
framework_test_LDFLAGS = $(GPT_LDFLAGS)

HTTP_COMMON_Sources = http_test_common.h http_test_common.c

HTTP_PERFORMANCE_Sources = globus_utp.h globus_utp_private.h globus_utp_main.c http_performance_common.h http_performance_common.c

http_header_test_SOURCES = http_header_test.c $(HTTP_COMMON_Sources)
http_header_test_LDFLAGS = $(GPT_LDFLAGS)

http_post_test_SOURCES = http_post_test.c $(HTTP_COMMON_Sources)
http_post_test_LDFLAGS = $(GPT_LDFLAGS)

http_put_test_SOURCES = http_put_test.c $(HTTP_COMMON_Sources)
http_put_test_LDFLAGS = $(GPT_LDFLAGS)

http_get_test_SOURCES = http_get_test.c $(HTTP_COMMON_Sources)
http_get_test_LDFLAGS = $(GPT_LDFLAGS)

http_pingpong_test_SOURCES = http_pingpong_test.c $(HTTP_PERFORMANCE_Sources)
http_pingpong_test_LDFLAGS = $(GPT_LDFLAGS)

http_timeout_test_SOURCES = http_timeout_test.c $(HTTP_COMMON_Sources)
http_timeout_test_LDFLAGS = $(GPT_LDFLAGS)

http_throughput_test_SOURCES = http_throughput_test.c $(HTTP_PERFORMANCE_Sources)
http_throughput_test_LDFLAGS = $(GPT_LDFLAGS)

http_timeout_test_SOURCES = http_timeout_test.c $(HTTP_COMMON_Sources) 		
http_timeout_test_LDFLAGS = $(GPT_LDFLAGS)

handle_create_from_url_test_SOURCES = handle_create_from_url_test.c
handle_create_from_url_test_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
