EXTRA_SCRIPTS = \
        TESTS.pl \
        TESTS-junit.pl

check_SCRIPTS = \
        grid-proxy-utils-test.pl \
        proxy-order-test.pl

check_DATA = \
	testwrapper \
        testcred.key \
        testcred.cert \
        testcredlink

test:
	chmod a+x $(pkgtest_SCRIPTS)
	perl ./TESTS.pl

junit:
	chmod a+x $(pkgtest_SCRIPTS)
	perl ./TESTS-junit.pl

TESTS = $(check_SCRIPTS)

LOG_COMPILER = $(builddir)/testwrapper

testwrapper:
	(echo '#! /bin/sh'; \
         echo 'export X509_USER_CERT=testcred.cert'; \
	 echo 'export X509_USER_KEY=testcred.key'; \
	 echo 'export X509_CERT_DIR=$(abs_builddir)'; \
         echo '"$$@"') > $@
	chmod a+x $@

testcred.key:
	umask 077; openssl genrsa -out $@ 1024

testcred.req: testcred.key
	printf "NA\nNA\nNA\nNA\nNA\nNA\nNA\n\n\n\n" | openssl req -new -key $< -out $@

testcred.cert: testcred.req testcred.key
	umask 022; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key -out $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	ln -s testcred.cert "$$linkname"

EXTRA_DIST = $(EXTRA_SCRIPTS) $(check_SCRIPTS)

.PHONY: test junit testcredlink
