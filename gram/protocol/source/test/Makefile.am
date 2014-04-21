AM_CPPFLAGS = -I$(top_srcdir) -I$(top_builddir) $(PACKAGE_DEP_CFLAGS)
LDADD = $(GSI_DRIVER_LIBS) $(DLPREOPEN_FORCE) \
    ../libglobus_gram_protocol.la $(PACKAGE_DEP_LIBS) -lltdl

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

if CYGPATH_W_DEFINED
X509_CERT_DIR = $$($(CYGPATH_W) "$(abs_builddir)")
else
X509_CERT_DIR = $(abs_builddir)
endif

TESTS_ENVIRONMENT = export \
    X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_CERT_DIR=$(X509_CERT_DIR);

LOG_COMPILER = $(LIBTOOL) --mode=execute $(GSI_DRIVER_LIBS) \
    $(srcdir)/gram-protocol-test-wrapper

testcred.key:
	umask 077; openssl genrsa -out $@ 1024

.key.req:
	printf "NA\nNA\nNA\nNA\nNA\n$$(openssl rand -base64 6)\n\n\n\n" | openssl req -new -key $< -out $@

.req.cert:
	umask 022; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key -out $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	cp testcred.cert "$$linkname"; \
        echo "$$linkname" > $@

EXTRA_DIST = $(check_SCRIPTS) 

CLEANFILES = testcred.key testcred.cert testcred.req

clean-local:
	if test -f testcredlink; then \
            rm -f $$(cat testcredlink) testcredlink; \
        fi
	rm -f *.valgrind *.vxml
SUFFIXES = .key .req .cert
