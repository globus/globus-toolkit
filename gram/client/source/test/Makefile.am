check_DATA = \
        testcred.key \
        testcred.cert \
        testcred.link

check_PROGRAMS = activate-test callback-contact-test

TESTS = $(check_PROGRAMS)

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_srcdir)
LDADD =  $(GLOBUS_XIO_GSI_DLPREOPEN) ../libglobus_gram_client.la $(PACKAGE_DEP_LIBS) -lltdl
AM_LDFLAGS = -dlpreopen force

X509_USER_CERT = testcred.cert
X509_USER_KEY = testcred.key
if USE_CYGPATH_W
X509_CERT_DIR = $$($(CYGPATH_W) $(abs_builddir))
else
X509_CERT_DIR = $(abs_builddir)
endif

TESTS_ENVIRONMENT = export \
    X509_USER_CERT=$(X509_USER_CERT) \
    X509_USER_KEY=$(X509_USER_KEY) \
    X509_CERT_DIR=$(X509_CERT_DIR);
LOG_COMPILER = $(LIBTOOL) --mode=execute $(GLOBUS_XIO_GSI_DLOPEN)

testcred.key:
	umask 077; openssl genrsa 1024 > $@

.key.req:
	printf "NA\nNA\nNA\nNA\nNA\nNA\nNA\n\n\n\n" | openssl req -new -key $< -out $@

.req.cert:
	umask 022; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key > $@


.cert.link:
	linkname="`openssl x509 -hash -noout -in $<`.0"; \
	rm -f "$$linkname"; \
	cp testcred.cert "$$linkname"; \
	echo "$$linkname" > $@

CLEANFILES = testcred.key testcred.cert
clean-local:
	@if test -r testcred.link ; then \
            rm -f $$(cat testcred.link) testcred.link ; \
        fi
SUFFIXES = .req .cert .key .link
