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
	umask 077; openssl genrsa -out $@ 1024

.key.req:
	printf "NA\nNA\nNA\nNA\nNA\nNA\nNA\n\n\n\n" | openssl req -new -key $< -out $@ -config openssl.cnf

.req.cert:
	umask 022; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key -out $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
        rm -f "$$linkname"; \
        cp testcred.cert "$$linkname"; \
	echo "$$linkname" > $@

AM_CPPFLAGS = -I$(top_srcdir) $(PACKAGE_DEP_CFLAGS) $(GSI_DRIVER_CFLAGS)
LDADD = ../libglobus_io.la $(PACKAGE_DEP_LIBS) $(GSI_DRIVER_LIBS) $(DLPREOPEN_FORCE) -lltdl

if CYGPATH_W_DEFINED
X509_CERT_DIR = $$($(CYGPATH_W) $(abs_builddir))
else
X509_CERT_DIR = $(abs_builddir)
endif

TESTS = $(check_SCRIPTS)
TESTS_ENVIRONMENT = export \
    X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_CERT_DIR=$(X509_CERT_DIR);

LOG_COMPILER = $(LIBTOOL) --mode=execute $(GSI_DRIVER_LIBS) $(srcdir)/globus-io-test-wrapper

EXTRA_DIST = \
	random_data.txt \
	$(check_SCRIPTS) \
        globus-io-test-wrapper
CLEANFILES = testcred.cert testcred.req testcred.key 
clean-local:
	if test -f testcredlink; then \
	    rm -f $$(cat testcredlink) testcredlink; \
	fi
SUFFIXES = .key .req .cert
