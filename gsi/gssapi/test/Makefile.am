include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata

AM_CFLAGS = $(GPT_CFLAGS) 

INCLUDES = $(GPT_INCLUDES)

Scripts= \
	TESTS.pl \
	TESTS-junit.pl \
        compare-name-test.pl \
        compare-name-test-gt2.pl \
        compare-name-test-rfc2818.pl \
        duplicate-name-test.pl \
        inquire-names-for-mech-test.pl \
	gssapi-anonymous-test.pl \
	gssapi-delegation-test.pl \
        gssapi-import-context-test.pl \
        gssapi-import-name.pl \
	gssapi-limited-delegation-test.pl \
	gssapi-delegation-compat-test.pl \
	gssapi-thread-test.pl \
	gssapi-context-test.pl \
	gssapi-expimp-test.pl \
	gssapi-acquire-test.pl \
	gssapi-inquire-sec-ctx-by-oid-test.pl \
        indicate-mechs-test.pl \
        nonterminated-export-cred-test.pl \
        release-name-test.pl

Data= \
        compare_name_test.txt \
        compare_name_test_strict_gt2.txt \
        compare_name_test_strict_rfc2818.txt \
        test.example.org.pem \
        star.example.org.pem \
        192.168.1.1.example.org.pem \
        192.168.1.1-2.example.org.pem

test_DATA = $(Data)

test_SCRIPTS = $(Scripts)

EXTRA_DIST = $(Data) \
	TESTS.pl.in \
	TESTS-junit.pl \
        compare-name-test.pl \
        compare-name-test-gt2.pl \
        compare-name-test-rfc2818.pl \
        duplicate-name-test.pl \
        inquire-names-for-mech-test.pl \
	gssapi-anonymous-test.pl \
	gssapi-delegation-test.pl \
        gssapi-import-context-test.pl \
        gssapi-import-name.pl \
	gssapi-limited-delegation-test.pl \
	gssapi-delegation-compat-test.pl \
	gssapi-thread-test.pl \
	gssapi-context-test.pl \
	gssapi-expimp-test.pl \
	gssapi-acquire-test.pl \
	gssapi-inquire-sec-ctx-by-oid-test.pl \
        indicate-mechs-test.pl \
        nonterminated-export-cred-test.pl \
        release-name-test.pl

test_PROGRAMS= \
        compare-name-test \
        duplicate-name-test \
	gssapi-anonymous-test \
	gssapi-delegation-test \
        gssapi-import-context-test \
        gssapi-import-name \
	gssapi-limited-delegation-test \
	gssapi-delegation-compat-test \
	gssapi-thread-test \
	gssapi-context-test \
	gssapi-expimp-test \
	gssapi-inquire-sec-ctx-by-oid-test \
	gssapi-acquire-test \
	gssapi-module-test \
        indicate-mechs-test \
        inquire-names-for-mech-test \
        nonterminated-export-cred-test \
        release-name-test

LDFLAGS += $(GPT_LDFLAGS)
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
gssapi_import_name_SOURCES = gssapi_import_name.c \
                             gssapi_test_utils.c \
                             gssapi_test_utils.h

compare_name_test_SOURCES = compare_name_test.c \
                                gssapi_test_utils.c \
                                gssapi_test_utils.h
inquire_names_for_mech_test_SOURCES = inquire_names_for_mech_test.c \
                                gssapi_test_utils.c \
                                gssapi_test_utils.h
release_name_test_SOURCES = release_name_test.c \
                                gssapi_test_utils.c \
                                gssapi_test_utils.h
duplicate_name_test_SOURCES = duplicate_name_test.c \
                                gssapi_test_utils.c \
                                gssapi_test_utils.h

indicate_mechs_test_SOURCES = indicate_mechs_test.c \
                                gssapi_test_utils.c \
                                gssapi_test_utils.h
nonterminated_export_cred_test_SOURCES = nonterminated_export_cred_test.c

test:
	chmod a+x $(Scripts)
	perl ./TESTS.pl

junit:
	chmod a+x $(Scripts)
	perl ./TESTS-junit.pl


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
