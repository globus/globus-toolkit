AUTOMAKE_OPTIONS = foreign
SUBDIRS = drivers

noinst_PROGRAMS =                       \
	framework_test			\
	http_header_test		\
	http_post_test			\
	http_put_test			\
	http_get_test			\
	http_pingpong_test		\
	http_timeout_test 		\
        handle_create_from_url_test     \
	http_throughput_test


pkgdata_DATA =                          \
	headers				\
	multi-line-header		\
	long-headers			\
	multi-headers			\
	large-file


noinst_SCRIPTS =                        \
	basic-test.pl                   \
	close-barrier-test.pl           \
	close-cancel-test.pl            \
	failure-test.pl                 \
	http-get-test.pl		\
	http-header-test.pl		\
	http-post-test.pl		\
	http-put-test.pl		\
        http-pingpong-test.pl		\
	http-timeout-test.pl		\
	http-throughput-test.pl         \
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
	test-common.pl                  \
	run-http-tests.pl               \
	run-xio-tests.pl                \
	run-all-tests.pl                \
	TESTS.pl TESTS-junit.pl


AM_CPPFLAGS = -I$(top_srcdir)/drivers $(PACKAGE_DEP_CFLAGS)
AM_LDFLAGS = $(GPT_LDFLAGS)
LDADD = $(PACKAGE_DEP_LIBS)

framework_test_SOURCES =                \
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

HTTP_COMMON_Sources = http_test_common.h http_test_common.c

HTTP_PERFORMANCE_Sources = globus_utp.h globus_utp_private.h globus_utp_main.c http_performance_common.h http_performance_common.c

http_header_test_SOURCES = http_header_test.c $(HTTP_COMMON_Sources)
http_post_test_SOURCES = http_post_test.c $(HTTP_COMMON_Sources)
http_put_test_SOURCES = http_put_test.c $(HTTP_COMMON_Sources)
http_get_test_SOURCES = http_get_test.c $(HTTP_COMMON_Sources)
http_pingpong_test_SOURCES = http_pingpong_test.c $(HTTP_PERFORMANCE_Sources)
http_timeout_test_SOURCES = http_timeout_test.c $(HTTP_COMMON_Sources)
http_throughput_test_SOURCES = http_throughput_test.c $(HTTP_PERFORMANCE_Sources)

test: $(noinst_SCRIPTS)
	chmod a+x $(noinst_SCRIPTS)
	$(LIBTOOL) --mode=execute -dlopen drivers/libglobus_xio_test_drivers.la \
        ./TESTS.pl

junit: $(noinst_SCRIPTS)
	chmod a+x $(noinst_SCRIPTS)
	$(LIBTOOL) --mode=execute -dlopen drivers/libglobus_xio_test_drivers.la \
        ./TESTS-junit.pl

EXTRA_DIST =                            \
        dirt.sh                         \
        $(noinst_SCRIPTS)               \
        $(pkgdata_DATA)                 \
	http-get-test.pl		\
	http-header-test.pl		\
	http-post-test.pl		\
	http-put-test.pl		\
        http-pingpong-test.pl		\
	http-timeout-test.pl		\
	http-throughput-test.pl

CLEANFILES = \
	http-get-test.pl		\
	http-header-test.pl		\
	http-post-test.pl		\
	http-put-test.pl		\
        http-pingpong-test.pl		\
	http-timeout-test.pl		\
	http-throughput-test.pl

.PHONY: test junit
