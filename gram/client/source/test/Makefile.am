Scripts = \
	TESTS.pl \
	callback-contact-test.pl \
	nonblocking-register-test.pl \
	ping-test.pl \
	register-test.pl \
	register-callback-test.pl

check_DATA = \
        testcred.key \
        testcred.cert \
        testcredlink

check_SCRIPTS = \
	$(Scripts) \
	run-tests.pl \
	two-phase-commit-test.pl \
	register-ping-test.pl \
	failed-job-two-phase-commit.pl

check_PROGRAMS = \
        failed-job-two-phase-commit \
	activate-test \
	callback-contact-test \
	cancel-test \
	refresh-credentials-test \
	nonblocking-register-test \
	ping-test \
	register-callback-test \
	register-cancel-test \
	register-refresh-credentials-test \
	status-test \
        set-credentials-test \
	status-test \
        stdio-size-test \
	stdio-update-test \
	register-test \
	register-ping-test \
        two-phase-commit-test \
        job-status-with-info-test \
        register-version-test \
        restart-to-new-url-test \
        stdio-update-test \
        stdio-update-after-failure-test \
        local-stdio-size-test \
        version-test

TESTS = \
	activate-test \
	callback-contact-test.pl \
	cancel-test \
	failed-job-two-phase-commit.pl \
	nonblocking-register-test.pl \
	ping-test.pl \
	refresh-credentials-test \
	register-callback-test.pl \
	register-cancel-test \
	register-ping-test.pl \
	register-refresh-credentials-test \
	register-test.pl \
	status-test \
	two-phase-commit-test.pl \
        job-status-with-info-test \
        local-stdio-size-test \
        register-version-test \
        restart-to-new-url-test \
        set-credentials-test \
        stdio-size-test \
        stdio-update-after-failure-test \
        stdio-update-test \
        version-test

TESTS_ENVIRONMENT = export \
    X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_CERT_DIR=$(abs_builddir) \
    PATH=$(GLOBUS_GRAM_JOB_MANAGER_PATH):$(PROXY_UTILS_PATH):$(CERT_UTILS_PATH):$${PATH};
LOG_COMPILER = $(srcdir)/gram-test-wrapper

EXTRA_DIST = $(Scripts) $(Data) run-tests.pl.in \
        two-phase-commit-test.pl.in \
	register-ping-test.pl.in \
        failed-job-two-phase-commit.pl.in \
	TESTS-junit.pl \
	gram-test-wrapper

junit: TESTS-junit.pl $(test_SCRIPTS) $(test_PROGRAMS)
	chmod +x $(test_SCRIPTS)
	PATH=${PATH}:. perl -I$(perlmoduledir) TESTS-junit.pl

AM_CPPFLAGS = $(TEST_PACKAGE_DEP_CFLAGS) $(PACKAGE_DEP_CFLAGS) -I$(top_srcdir)
LDADD = $(top_builddir)/libglobus_gram_client.la \
	$(TEST_PACKAGE_DEP_LIBS) \
	$(PACKAGE_DEP_LIBS)

testcred.key:
	openssl genrsa -out $@ 1024 && chmod 0600 $@

.key.req:
	printf "NA\nNA\nNA\nNA\nNA\nNA\nNA\n\n\n\n" | openssl req -new -key $< -out $@

.req.cert:
	openssl x509 -req -days 365 -in testcred.req -signkey testcred.key -out $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	cp testcred.cert "$$linkname"

.PHONY: junit

SUFFIXES = .req .cert .key
