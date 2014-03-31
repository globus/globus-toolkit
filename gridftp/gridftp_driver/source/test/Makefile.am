AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_srcdir)
globus_gridftp_driver_test_LDADD = $(PACKAGE_DEP_LIBS)

check_SCRIPTS = globus_gridftp_driver_test.pl
check_PROGRAMS = globus_gridftp_driver_test
check_DATA = testcred.key testcred.cert testcredlink gridmap

TESTS = $(check_SCRIPTS)
TESTS_ENVIRONMENT = \
    export X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_CERT_DIR=$(abs_builddir) \
    GRIDMAP=$(abs_builddir)/gridmap \
    PATH="$(GRIDFTP_SBINDIR):$(srcdir):$(abs_builddir):$${PATH}";
LOG_COMPILER = $(LIBTOOL) --mode=execute \
	-dlopen $(GLOBUS_XIO_GSI_DRIVER) \
	-dlopen $(GLOBUS_XIO_PIPE_DRIVER) \
	-dlopen $(top_builddir)/libglobus_xio_gridftp_driver.la \
	$(srcdir)/test-wrapper

EXTRA_DIST = $(check_SCRIPTS) test-wrapper

testcred.key:
	umask 077; openssl genrsa -out $@ 1024

.key.req:
	printf "NA\nNA\nNA\nNA\nNA\n$$(openssl rand -base64 6)\n\n\n\n" | openssl req -new -key $< -out $@

.req.cert:
	umask 077; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key -out $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	cp testcred.cert "$$linkname" ; \
	echo "$$linkname" > $@

gridmap: testcred.cert
	subject=`openssl x509 -subject -noout -in testcred.cert | sed -e 's/subject= *//'` ; \
        echo "\"$$subject\" $${LOGNAME:-`id -un`}" > gridmap


CLEANFILES = testcred.key testcred.cert testcred.req gridmap

clean-local:
	if [ -f testcredlink ]; then \
	    rm -f $$(cat testcredlink) testcredlink; \
	fi
SUFFIXES = .key .req .cert
