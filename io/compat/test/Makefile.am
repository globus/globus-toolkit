check_PROGRAMS = \
	globus_io_tcp_test \
	globus_io_tcp_test_server \
	globus_io_tcp_test_client \
	globus_io_file_test \
	globus_io_authorization_test

check_SCRIPTS = \
	globus-io-authorization-test.pl \
        globus-io-file-test.pl \
        globus-io-tcp-test.pl

check_DATA = \
        testcred.key \
        testcred.cert \
        testcredlink

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

AM_CPPFLAGS = -I$(top_srcdir) $(PACKAGE_DEP_CFLAGS)
LDADD = ../libglobus_io.la $(PACKAGE_DEP_LIBS)

TESTS = $(check_SCRIPTS)
TESTS_ENVIRONMENT = export \
    X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_CERT_DIR=$(abs_builddir); \
    if [ -f $(GLOBUS_XIO_GSI_DRIVER_LIBDIR)/libglobus_xio_gsi_driver.la ]; then \
        libtoolline="../libtool --mode=execute -dlopen $(GLOBUS_XIO_GSI_DRIVER_LIBDIR)/libglobus_xio_gsi_driver.la"; \
    fi ; \
    $$libtoolline


EXTRA_DIST = \
	$(check_SCRIPTS) \
	TESTS.pl \
	TESTS-junit.pl

test:
	chmod a+x $(test_SCRIPTS)
	perl ./TESTS.pl

junit:
	chmod a+x $(test_SCRIPTS)
	perl ./TESTS-junit.pl

.PHONY: test junit testcredlink
