include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata 

Sources=                                \
    test_common.c                       \
    driver_stack.c                      \
    blocking_dd_test.c                  \
    unload_test.c                       \
    framework_test.c                    \
    space_test.c                        \
    timeout_test.c                      \
    close_barrier_test.c                \
    close_cancel_test.c                 \
    cancel_test.c                       \
    server2_test.c                      \
    attr_test.c                         \
    block_barrier_test.c                \
    read_barrier_test.c

INCLUDES += $(GPT_INCLUDES)

test_PROGRAMS=                          \
	framework_test			\
	http_header_test		\
	http_post_test			\
	http_put_test			\
	http_get_test

pkgdata_DATA =				\
	headers				\
	multi-line-header		\
	long-headers			\
	multi-headers			\
	large-file

test_SCRIPTS =				\
	http-get-test.pl		\
	http-header-test.pl		\
	http-post-test.pl		\
	http-put-test.pl		\
	run-http-tests.pl
		

framework_test_SOURCES = $(Sources)
framework_test_LDFLAGS = $(GPT_LDFLAGS)
framework_test_LDADD = $(GPT_PGM_LINKS) 

HTTP_COMMON_Sources = http_test_common.h http_test_common.c

http_header_test_SOURCES = http_header_test.c $(HTTP_COMMON_Sources)
http_header_test_LDFLAGS = $(GPT_LDFLAGS)
http_header_test_LDADD = $(GPT_PGM_LINKS) 

http_post_test_SOURCES = http_post_test.c $(HTTP_COMMON_Sources)
http_post_test_LDFLAGS = $(GPT_LDFLAGS)
http_post_test_LDADD = $(GPT_PGM_LINKS) 

http_put_test_SOURCES = http_put_test.c $(HTTP_COMMON_Sources)
http_put_test_LDFLAGS = $(GPT_LDFLAGS)
http_put_test_LDADD = $(GPT_PGM_LINKS) 

http_get_test_SOURCES = http_get_test.c $(HTTP_COMMON_Sources)
http_get_test_LDFLAGS = $(GPT_LDFLAGS)
http_get_test_LDADD = $(GPT_PGM_LINKS) 

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
