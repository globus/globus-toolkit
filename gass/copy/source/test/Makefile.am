EXTRA_SCRIPTS = TESTS.pl test-wrapper

check_SCRIPTS = \
        guc-cc.pl \
        guc-fw.pl \
        guc-pp-cc.pl \
        guc-simple.pl \
        guc-stack.pl

check_DATA =  \
        testcred.key \
        testcred.cert \
        testcredlink \
        gridmap

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

gridmap: testcred.cert
	subject=`openssl x509 -subject -noout -in testcred.cert | sed -e 's/subject= *//'` ; \
        echo "\"$$subject\" `id -un`" > gridmap

TESTS = $(check_SCRIPTS)
AM_TESTS_ENVIRONMENT = \
    export X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_CERT_DIR=$(abs_builddir) \
    GRIDMAP=$(abs_builddir)/gridmap;
LOG_COMPILER = $(srcdir)/test-wrapper

CLEANFILES = testcred.key testcred.cert testcred.req gridmap
EXTRA_DIST = $(check_SCRIPTS) $(EXTRA_SCRIPTS)
