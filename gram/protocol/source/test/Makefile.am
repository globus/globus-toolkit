AM_CPPFLAGS = -I$(top_srcdir) -I$(top_builddir) $(PACKAGE_DEP_CFLAGS)
LDADD = ../libglobus_gram_protocol.la $(PACKAGE_DEP_LIBS)

check_SCRIPTS = gram-protocol-test-wrapper 

check_PROGRAMS = \
	allow-attach-test \
	delegation-test \
	io-test \
	pack-test \
        create-extensions-test \
        error-test \
        pack-with-extensions-test \
        unpack-job-request-reply-with-extensions-test \
        unpack-message-test \
        unpack-status-reply-with-extensions-test \
        unpack-with-extensions-test

check_DATA = \
        testcred.key \
        testcred.cert \
        testcredlink

TESTS = $(check_PROGRAMS)
TESTS_ENVIRONMENT = export \
    X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_CERT_DIR=$(abs_builddir);

LOG_COMPILER = $(LIBTOOL) --mode=execute --dlopen $(GLOBUS_XIO_GSI_DRIVER_LIBDIR)/libglobus_xio_gsi_driver.la $(srcdir)/gram-protocol-test-wrapper
testcred.key:
	umask 077; openssl genrsa -out $@ 1024

testcred.req: testcred.key
	printf "NA\nNA\nNA\nNA\nNA\n$$(openssl rand -base64 6)\n\n\n\n" | openssl req -new -key $< -out $@

testcred.cert: testcred.req testcred.key
	umask 022; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key -out $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	ln -s testcred.cert "$$linkname"; \
        echo "$$linkname" > $@

EXTRA_DIST = $(check_SCRIPTS) 

CLEANFILES = testcred.key testcred.cert testcred.req

clean-local:
	if test -f testcredlink; then \
            rm -f $$(cat testcredlink) testcredlink; \
        fi
	rm -f *.valgrind *.vxml
