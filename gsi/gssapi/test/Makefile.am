include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata

Sources= \
	gssapi_anonymous_test.c \
	gssapi_delegation_test.c \
	gssapi_limited_delegation_test.c \
	gssapi_delegation_compat_test.c \
	gssapi_test_utils.c \
	gssapi_test_utils.h \
	gssapi_thread_test.c 
#	gssapi_group_test.c \

INCLUDES += $(GPT_INCLUDES)

Scripts= \
	TESTS.pl \
	gssapi-anonymous-test.pl \
	gssapi-delegation-test.pl \
	gssapi-limited-delegation-test.pl \
	gssapi-delegation-compat-test.pl \
	gssapi-thread-test.pl \
	run-gssapi-tests.pl
#	gssapi-group-test.pl \

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
#	gssapi-group-test.stdout \

test_DATA = $(Data)

test_SCRIPTS = $(Scripts)

EXTRA_DIST = $(Scripts) $(Data)

test_PROGRAMS= \
	gssapi-anonymous-test \
	gssapi-delegation-test \
	gssapi-limited-delegation-test \
	gssapi-delegation-compat-test \
	gssapi-thread-test
#	gssapi-group-test \

gssapi_anonymous_test_SOURCES = gssapi_anonymous_test.c

gssapi_anonymous_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_anonymous_test_LDADD = $(GPT_PGM_LINKS)


#gssapi_group_test_SOURCES = gssapi_group_test.c

#gssapi_group_test_LDFLAGS = $(GPT_LDFLAGS)

#gssapi_group_test_LDADD = $(GPT_PGM_LINKS)


gssapi_delegation_test_SOURCES = gssapi_delegation_test.c

gssapi_delegation_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_delegation_test_LDADD = $(GPT_PGM_LINKS)


gssapi_limited_delegation_test_SOURCES = gssapi_limited_delegation_test.c

gssapi_limited_delegation_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_limited_delegation_test_LDADD = $(GPT_PGM_LINKS)


gssapi_delegation_compat_test_SOURCES = gssapi_delegation_compat_test.c

gssapi_delegation_compat_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_delegation_compat_test_LDADD = $(GPT_PGM_LINKS)

gssapi_thread_test_SOURCES = gssapi_thread_test.c \
                             gssapi_test_utils.c \
                             gssapi_test_utils.h

gssapi_thread_test_LDFLAGS = $(GPT_LDFLAGS)

gssapi_thread_test_LDADD = $(GPT_PGM_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

