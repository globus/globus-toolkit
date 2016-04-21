check_PROGRAMS = \
        cmp_alias_ent_test \
        sharing_allowed_test

check_DATA = \
        testcred.key \
        testcred.cert \
        testcredlink

check_SCRIPTS = setup-chroot-test

TESTS = \
	cmp_alias_ent_test\
	setup-chroot-test \
	sharing_allowed_test
TESTS_ENVIRONMENT = \
	export X509_CERT_DIR="$(abs_builddir)/certificates" \
	       PATH="$(abs_srcdir)/..:$$PATH";
LOG_COMPILER = $(FAKEROOT) ../libtool --mode=execute $(MODULE_DLOPEN)

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(srcdir)/..
LDADD = ../libglobus_gridftp_server.la \
        $(MODULE_DLPREOPEN) $(PACKAGE_DEP_LIBS) -lltdl

LDFLAGS = -dlpreopen force

testcred.key:
	umask 077; openssl genrsa 1024 > $@

.key.req:
	printf "NA\nNA\nNA\nNA\nNA\nNA\nNA\n\n\n\n" | openssl req -new -config $(srcdir)/openssl.cnf -key $< > $@

.req.cert:
	umask 022; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key > $@

testcredlink: testcred.cert
	$(MKDIR_P) certificates
	linkname="certificates/`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	cp testcred.cert "$$linkname" && \
        echo "$$linkname" > testcredlink

CLEANFILES = testcred.key testcred.cert testcred.req cert_chain.txt

clean-local:
	@if [ -f testcredlink ]; then \
            rm -f $$(cat testcredlink) testcredlink ; \
	    rm -rf certificates; \
        fi

SUFFIXES = .key .req .cert 

EXTRA_DIST = openssl.cnf $(check_SCRIPTS)
