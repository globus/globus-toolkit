include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata

AM_CFLAGS = $(GPT_CFLAGS) 

INCLUDES = $(GPT_INCLUDES)

Scripts= \
	TESTS.pl \
	gssapi-anonymous-test.pl \
	gssapi-delegation-test.pl \
        gssapi-import-context-test.pl \
	gssapi-limited-delegation-test.pl \
	gssapi-delegation-compat-test.pl \
	gssapi-thread-test.pl \
	gssapi-context-test.pl \
	gssapi-expimp-test.pl \
	gssapi-acquire-test.pl \
	gssapi-inquire-sec-ctx-by-oid-test.pl \
	run-gssapi-tests.pl

Data= \
	gssapi-anonymous-test.stdout \
	gssapi-delegation-test.stdout \
	gssapi-limited-delegation-test.stdout \
	gssapi-delegation-compat-test.stdout \
	gssapi-anonymous-test.stderr \
	gssapi-delegation-test.stderr \
	gssapi-limited-delegation-test.stderr \
	gssapi-delegation-compat-test.stderr

test_DATA = $(Data)

test_SCRIPTS = $(Scripts)

EXTRA_DIST = $(Scripts) $(Data)

test_PROGRAMS= \
	gssapi-anonymous-test \
	gssapi-delegation-test \
        gssapi-import-context-test \
	gssapi-limited-delegation-test \
	gssapi-delegation-compat-test \
	gssapi-thread-test \
	gssapi-context-test \
	gssapi-expimp-test \
	gssapi-inquire-sec-ctx-by-oid-test \
	gssapi-acquire-test \
	gssapi-module-test

LDFLAGS = $(GPT_LDFLAGS)
LDADD = $(GPT_PGM_LINKS)

gssapi_anonymous_test_SOURCES = gssapi_anonymous_test.c

gssapi_delegation_test_SOURCES = \
				gssapi_delegation_test.c \
				gssapi_openssl.h \
				globus_gsi_gss_constants.h

gssapi_limited_delegation_test_SOURCES = \
				gssapi_limited_delegation_test.c \
				gssapi_openssl.h \
				globus_gsi_gss_constants.h

gssapi_delegation_compat_test_SOURCES = \
				gssapi_delegation_compat_test.c \
				gssapi_openssl.h \
				globus_gsi_gss_constants.h

gssapi_thread_test_SOURCES = gssapi_thread_test.c \
                             gssapi_test_utils.c \
                             gssapi_test_utils.h

gssapi_context_test_SOURCES =	gssapi_context_test.c \
				gssapi_test_utils.c \
				gssapi_test_utils.h

gssapi_acquire_test_SOURCES =	gssapi_acquire_test.c

gssapi_expimp_test_SOURCES =	gssapi_expimp_test.c \
				gssapi_test_utils.c \
				gssapi_test_utils.h

gssapi_inquire_sec_ctx_by_oid_test_SOURCES = \
				gssapi_inquire_sec_ctx_by_oid_test.c \
				gssapi_test_utils.c \
				gssapi_test_utils.h

gssapi_module_test_SOURCES = gssapi_module_test.c

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
