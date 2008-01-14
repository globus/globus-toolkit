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
#	gssapi-group-test.pl

Data= \
	gssapi-anonymous-test.stdout \
	gssapi-delegation-test.stdout \
	gssapi-limited-delegation-test.stdout \
	gssapi-delegation-compat-test.stdout \
	gssapi-anonymous-test.stderr \
	gssapi-delegation-test.stderr \
	gssapi-limited-delegation-test.stderr \
	gssapi-delegation-compat-test.stderr \
	gssapi-group-test.stderr \
	dc31a685.0 \
	dc31a685.signing_policy \
	testcred.pem
#	gssapi-group-test.stdout

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


gssapi_anonymous_test_SOURCES = gssapi_anonymous_test.c

gssapi_anonymous_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_anonymous_test_LDADD = $(GPT_PGM_LINKS)


#gssapi_group_test_SOURCES = \
#			gssapi_group_test.c \
#			gssapi_openssl.h \
#			globus_gsi_gss_constants.h

#gssapi_group_test_LDFLAGS = $(GPT_LDFLAGS)

#gssapi_group_test_LDADD = $(GPT_PGM_LINKS)


gssapi_delegation_test_SOURCES = \
				gssapi_delegation_test.c \
				gssapi_openssl.h \
				globus_gsi_gss_constants.h

gssapi_delegation_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_delegation_test_LDADD = $(GPT_PGM_LINKS)


gssapi_limited_delegation_test_SOURCES = \
				gssapi_limited_delegation_test.c \
				gssapi_openssl.h \
				globus_gsi_gss_constants.h

gssapi_limited_delegation_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_limited_delegation_test_LDADD = $(GPT_PGM_LINKS)


gssapi_delegation_compat_test_SOURCES = \
				gssapi_delegation_compat_test.c \
				gssapi_openssl.h \
				globus_gsi_gss_constants.h

gssapi_delegation_compat_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_delegation_compat_test_LDADD = $(GPT_PGM_LINKS)

gssapi_thread_test_SOURCES = gssapi_thread_test.c \
                             gssapi_test_utils.c \
                             gssapi_test_utils.h

gssapi_thread_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_thread_test_LDADD = $(GPT_PGM_LINKS)

gssapi_context_test_SOURCES =	gssapi_context_test.c \
				gssapi_test_utils.c \
				gssapi_test_utils.h

gssapi_context_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_context_test_LDADD = $(GPT_PGM_LINKS)

gssapi_acquire_test_SOURCES =	gssapi_acquire_test.c

gssapi_acquire_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_acquire_test_LDADD = $(GPT_PGM_LINKS)

gssapi_expimp_test_SOURCES =	gssapi_expimp_test.c \
				gssapi_test_utils.c \
				gssapi_test_utils.h

gssapi_expimp_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_expimp_test_LDADD = $(GPT_PGM_LINKS)

gssapi_inquire_sec_ctx_by_oid_test_SOURCES = \
				gssapi_inquire_sec_ctx_by_oid_test.c \
				gssapi_test_utils.c \
				gssapi_test_utils.h

gssapi_inquire_sec_ctx_by_oid_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_inquire_sec_ctx_by_oid_test_LDADD = $(GPT_PGM_LINKS)

gssapi_module_test_SOURCES = gssapi_module_test.c

gssapi_module_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_module_test_LDADD = $(GPT_PGM_LINKS)

gssapi_import_context_test_LDFLAGS = $(GPT_LDFLAGS)
gssapi_import_context_test_LDADD = $(GPT_PGM_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

