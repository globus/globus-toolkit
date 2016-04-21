AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_srcdir)/library
LDADD = libgssapi_test_utils.la \
        ../library/libglobus_gssapi_gsi.la \
        $(PACKAGE_DEP_LIBS) \
        -lltdl

check_LTLIBRARIES = libgssapi_test_utils.la

check_DATA_real = \
        compare_name_test_hybrid.txt \
        compare_name_test_strict_gt2.txt \
        compare_name_test_strict_rfc2818.txt \
        test.example.org.pem \
        star.example.org.pem \
        192.168.1.1.example.org.pem \
        192.168.1.1-2.example.org.pem

testcred_links = testcred.link testcred-nocn.link

check_DATA = $(check_DATA_real) \
        testcred.key \
        testcred.cert \
        $(testcred_links) \
        testcred-nocn.key \
        testcred-nocn.cert \
        copy_cases \
        $(THREAD_TESTS)

check_SCRIPTS = \
        compare-name-test-hybrid.pl \
        compare-name-test-gt2.pl \
        compare-name-test-rfc2818.pl \
        gssapi-thread-test-wrapper

check_PROGRAMS= \
        compare-name-test \
        duplicate-name-test \
	error-test \
	gssapi-anonymous-test \
	gssapi-delegation-test \
        gssapi_expimp_cred_test \
        gssapi-import-context-test \
        gssapi-import-name \
	gssapi-limited-delegation-test \
	gssapi-delegation-compat-test \
	gssapi-context-test \
	gssapi-expimp-test \
	gssapi-inquire-sec-ctx-by-oid-test \
	gssapi-acquire-test \
	gssapi-module-test \
        indicate-mechs-test \
        inquire-names-for-mech-test \
        nonterminated-export-cred-test \
        release-name-test \
        gssapi-thread-test

TESTS = $(check_SCRIPTS) \
        duplicate-name-test \
	error-test \
        inquire-names-for-mech-test \
	gssapi-anonymous-test \
	gssapi-context-test \
	gssapi-delegation-test \
        gssapi_expimp_cred_test \
        gssapi-import-context-test \
        gssapi-import-name \
	gssapi-limited-delegation-test \
	gssapi-delegation-compat-test \
	gssapi-expimp-test \
	gssapi-acquire-test \
        indicate-mechs-test \
	gssapi-inquire-sec-ctx-by-oid-test \
        nonterminated-export-cred-test \
        release-name-test 

LOG_COMPILER = $(srcdir)/gssapi-test-wrapper

TEST_DATA_DIR = $(srcdir)

if CYGPATH_W_DEFINED
X509_CERT_DIR = $$($(CYGPATH_W) $(abs_builddir))
else
X509_CERT_DIR = $(abs_builddir)
endif

TESTS_ENVIRONMENT = export \
    X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_USER_CERT2=testcred-nocn.cert \
    X509_USER_KEY2=testcred-nocn.key \
    X509_CERT_DIR=$(X509_CERT_DIR) \
    THREAD_MODELS=$(GLOBUS_THREAD_MODELS) \
    TEST_DATA_DIR=$(TEST_DATA_DIR) \
    TEST_CERT_DIR=$(srcdir);

THREAD_TESTS-undefined $(THREAD_TESTS):
	${srcdir}/create-thread-test "$@"
	
libgssapi_test_utils_la_SOURCES = \
        gssapi_test_utils.c \
        gssapi_test_utils.h

gssapi_anonymous_test_SOURCES = \
        gssapi_anonymous_test.c
gssapi_delegation_test_SOURCES = \
        gssapi_delegation_test.c \
	$(top_srcdir)/library/gssapi_openssl.h \
	$(top_srcdir)/library/globus_gsi_gss_constants.h

gssapi_limited_delegation_test_SOURCES = gssapi_limited_delegation_test.c 
gssapi_delegation_compat_test_SOURCES = gssapi_delegation_compat_test.c

gssapi_thread_test_SOURCES = gssapi_thread_test.c
gssapi_thread_test_LDADD = $(LDADD) $(THREAD_TEST_DLPREOPEN)
gssapi_thread_test_LDFLAGS = -dlpreopen force
gssapi_thread_test_CPPFLAGS = $(AM_CPPFLAGS)

gssapi_import_context_test_SOURCES = gssapi_import_context_test.c
gssapi_context_test_SOURCES =	gssapi_context_test.c 
gssapi_acquire_test_SOURCES =	gssapi_acquire_test.c
gssapi_expimp_test_SOURCES =	gssapi_expimp_test.c 

gssapi_inquire_sec_ctx_by_oid_test_SOURCES = \
				gssapi_inquire_sec_ctx_by_oid_test.c 

gssapi_module_test_SOURCES = gssapi_module_test.c
gssapi_import_name_SOURCES = gssapi_import_name.c 
compare_name_test_SOURCES = compare_name_test.c
inquire_names_for_mech_test_SOURCES = inquire_names_for_mech_test.c
release_name_test_SOURCES = release_name_test.c
duplicate_name_test_SOURCES = duplicate_name_test.c
indicate_mechs_test_SOURCES = indicate_mechs_test.c
nonterminated_export_cred_test_SOURCES = nonterminated_export_cred_test.c

testcred.key testcred-nocn.key:
	umask 077; openssl genrsa 1024 > $@
.key.req:
	printf "NA\nNA\nNA\nNA\nNA\nNA\nNA\n\n\n\n" | openssl req -new -config $*.cnf -key $< > $@

.req.cert:
	umask 022; openssl x509 -req -days 365 -in $< -signkey $*.key > $@

.cert.link:
	linkname="`openssl x509 -hash -noout -in $<`.0"; \
	rm -f "$$linkname"; \
	cp $< "$$linkname"; \
        echo "$$linkname" > $@

EXTRA_DIST = \
        $(check_DATA_real) \
        $(check_SCRIPTS) \
        gssapi-test-wrapper \
        create-thread-test \
        gssapi-thread-test-wrapper

CLEANFILES = testcred.key testcred.cert testcred.req \
             testcred-nocn.key testcred-nocn.cert testcred-nocn.req \
             cert_chain.txt $(THREAD_TESTS)

copy_cases:
	if [ "$(VPATH)" != "" ]; then \
            for d in $(check_DATA_real); do \
                cp $(srcdir)/$$d $(builddir); \
            done; \
        fi
	touch $@
clean-local:
	@for linkfile in $(testcred_links)""; do \
	    if [ -f $$linkfile ]; then \
	        rm -f $$(cat $$linkfile) $$linkfile; \
	    fi; \
	done
	@if [ "$(VPATH)" != "" ]; then \
            for d in $(check_DATA_real); do \
                if [ -f $(builddir)/$$d ]; then \
                    rm -f $(builddir)/$$d; \
                fi; \
            done; \
        fi
	rm -f copy_cases

SUFFIXES = .key .req .cert .link
