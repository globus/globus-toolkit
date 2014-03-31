check_SCRIPTS = \
        grid-proxy-utils-test.pl \
        proxy-order-test.pl

check_DATA = \
        testcred.key \
        testcred.cert \
        testcredlink

if CYGPATH_W_DEFINED
X509_CERT_DIR = $$($(CYGPATH_W) $(abs_builddir))
else
X509_CERT_DIR = $(abs_builddir)
endif

TESTS = $(check_SCRIPTS)
TESTS_ENVIRONMENT = \
	export X509_USER_CERT=testcred.cert \
	       X509_USER_KEY=testcred.key \
	       X509_CERT_DIR=$(X509_CERT_DIR) \
	       PATH=../programs:$$PATH;

testcred.key:
	umask 077; openssl genrsa -out $@ 1024

.key.req:
	printf "NA\nNA\nNA\nNA\nNA\nNA\nNA\n\n\n\n" | openssl req -new -key $< -out $@

.req.cert:
	umask 022; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key -out $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	cp testcred.cert "$$linkname"; \
	echo "$$linkname" > $@

CLEANFILES = testcred.cert testcred.key testcred.req
clean-local:
	if test -f testcredlink; then \
	    rm -f $$(cat testcredlink) testcredlink; \
	fi
EXTRA_DIST = $(EXTRA_SCRIPTS) $(check_SCRIPTS)
SUFFIXES = .key .req .cert
