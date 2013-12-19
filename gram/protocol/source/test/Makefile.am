AM_CPPFLAGS = -I$(top_srcdir) -I$(top_builddir) $(PACKAGE_DEP_CFLAGS)
LDADD = ../libglobus_gram_protocol.la $(PACKAGE_DEP_LIBS)

check_SCRIPTS = \
	allow-attach-test.pl \
	error-test.pl \
	pack-test.pl \
        create-extensions-test.pl \
        pack-with-extensions-test.pl \
        unpack-message-test.pl \
        unpack-with-extensions-test.pl \
        unpack-job-request-reply-with-extensions-test.pl \
        unpack-status-reply-with-extensions-test.pl

check_PROGRAMS = \
	allow-attach-test \
	delegation-test \
        error-test \
	io-test \
	pack-test \
        create-extensions-test \
        pack-with-extensions-test \
        unpack-message-test \
        unpack-with-extensions-test \
        unpack-job-request-reply-with-extensions-test \
        unpack-status-reply-with-extensions-test

check_DATA = \
        testcred.key \
        testcred.cert \
        testcredlink

TESTS = $(check_PROGRAMS)
TESTS_ENVIRONMENT = export \
    X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_CERT_DIR=$(abs_builddir);

testcred.key:
	openssl genrsa -out $@ 1024 && chmod 0600 $@

testcred.req: testcred.key
	printf "NA\nNA\nNA\nNA\nNA\nNA\nNA\n\n\n\n" | openssl req -new -key $< -out $@

testcred.cert: testcred.req testcred.key
	openssl x509 -req -days 365 -in testcred.req -signkey testcred.key -out $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	ln -s testcred.cert "$$linkname"

EXTRA_DIST =  \
        $(check_SCRIPTS) \
        TESTS.pl \
        TESTS-junit.pl

CLEANFILES = $(check_DATA)

test: $(pkgtest_PROGRAMS) $(pkgtest_SCRIPTS)
	perl -I${perlmoduledir} TESTS.pl

junit: $(pkgtest_PROGRAMS) $(pkgtest_SCRIPTS)
	perl -I${perlmoduledir} TESTS-junit.pl

.PHONY: test junit testcredlink

