check_PROGRAMS = authz_cred_test
check_LTLIBRARIES = libglobus_authz_test_callout.la
check_DATA = \
        authz_test_callout.conf \
        testcred.key \
        testcred.cert \
        testcredlink

TESTS = $(check_PROGRAMS)
TESTS_ENVIRONMENT = export \
    X509_USER_CERT=$(abs_builddir)/testcred.cert \
    X509_USER_KEY=$(abs_builddir)/testcred.key \
    X509_CERT_DIR=$(abs_builddir) \
    GSI_AUTHZ_CONF=$(abs_srcdir)/authz_test_callout.conf;
LOG_COMPILER = $(top_builddir)/libtool --mode=execute -dlopen libglobus_authz_test_callout.la

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_srcdir)
LDADD = $(PACKAGE_DEP_LIBS)

authz_cred_test_LDFLAGS = -rpath $(abs_builddir)
authz_cred_test_LDADD = ../libglobus_authz.la $(LDADD)
authz_cred_test_SOURCES = authz_cred_test.c 

libglobus_authz_test_callout_la_SOURCES = authz_test_callout.c
libglobus_authz_test_callout_la_LIBADD = $(GPT_LIB_LINKS)

libglobus_authz_test_callout_la_LDFLAGS = \
	-module \
        -no-undefined \
        -rpath $(abs_builddir)

testcred.key:
	umask 077 ; openssl genrsa -out $@ 1024

testcred.req: testcred.key
	printf "NA\nNA\nNA\nNA\nNA\nNA\n$$(openssl rand -base64 6)\n\n\n\n" | openssl req -new -key $< -out $@

testcred.cert: testcred.req testcred.key
	umask 022; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key -out $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	ln -s testcred.cert "$$linkname" ; \
	echo "$$linkname" > $@

CLEANFILES = testcred.key testcred.cert testcred.req

clean-local:
	if test -f testcredlink; then \
            rm -f $$(cat testcredlink) testcredlink; \
        fi
	
EXTRA_DIST = authz_test_callout.conf
