include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata

Sources= \
	globus_openssl_error_test.c

AM_CFLAGS = $(GPT_CFLAGS) 

INCLUDES = $(GPT_INCLUDES)

Scripts= \
	TESTS.pl \
	globus-openssl-error-test.pl \
	run-openssl-error-tests.pl

Data= \
	globus_openssl_error_test.stdout

test_DATA = $(Data)

test_SCRIPTS = $(Scripts)

EXTRA_DIST = $(Scripts) $(Data)

test_PROGRAMS= \
	globus_openssl_error_test

globus_openssl_error_test_SOURCES = globus_openssl_error_test.c
globus_openssl_error_test_LDFLAGS = $(GPT_LDFLAGS)
globus_openssl_error_test_LDADD = $(GPT_PGM_LINKS)


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top


