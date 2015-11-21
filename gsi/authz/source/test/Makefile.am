check_PROGRAMS = authz_cred_test
check_LTLIBRARIES = libglobus_authz_test_callout.la
check_DATA = \
        authz_test_callout.conf \
        testcred.key \
        testcred.cert \
        testcredlink

X509_USER_CERT=testcred.cert
X509_USER_KEY=testcred.key
X509_CERT_DIR=.
if CYGPATH_W_DEFINED
GSI_AUTHZ_CONF=$$($(CYGPATH_W) $(abs_srcdir)/authz_test_callout.conf)
else
GSI_AUTHZ_CONF=$(abs_srcdir)/authz_test_callout.conf
endif

TESTS = $(check_PROGRAMS)
TESTS_ENVIRONMENT = export \
    X509_USER_CERT=$(X509_USER_CERT) \
    X509_USER_KEY=$(X509_USER_KEY) \
    X509_CERT_DIR=$(X509_CERT_DIR) \
    GSI_AUTHZ_CONF=$(GSI_AUTHZ_CONF);
LOG_COMPILER = $(top_builddir)/libtool --mode=execute -dlopen libglobus_authz_test_callout.la

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_srcdir)
LDADD = $(PACKAGE_DEP_LIBS) -lltdl

authz_cred_test_LDFLAGS = -rpath $(abs_builddir) -dlopen libglobus_authz_test_callout.la
authz_cred_test_LDADD = ../libglobus_authz.la $(LDADD)
authz_cred_test_SOURCES = authz_cred_test.c 
authz_cred_test_DEPENDENCIES = libglobus_authz_test_callout.la

libglobus_authz_test_callout_la_SOURCES = authz_test_callout.c
libglobus_authz_test_callout_la_LIBADD = $(GPT_LIB_LINKS)

libglobus_authz_test_callout_la_LDFLAGS = \
	-module \
	-no-undefined \
	-avoid-version \
	-rpath $(abs_builddir)

testcred.key:
	umask 077 ; openssl genrsa 1024 > $@

.key.req:
	printf "NA\nNA\nNA\nNA\nNA\nNA\nNA\n\n\n\n" | openssl req -new -key $< > $@ -config openssl.cnf

.req.cert:
	umask 022; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key > $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	cp testcred.cert "$$linkname" ; \
	echo "$$linkname" > $@

CLEANFILES = testcred.key testcred.cert testcred.req

clean-local:
	if test -f testcredlink; then \
	    rm -f $$(cat testcredlink) testcredlink; \
	fi

EXTRA_DIST = authz_test_callout.conf
SUFFIXES = .key .req .cert
