EXTRA_SCRIPTS = test-wrapper

check_SCRIPTS = \
        guc-cc.pl \
        guc-fw.pl \
        guc-pp-cc.pl \
        guc-stack.pl

check_DATA =  \
        testcred.key \
        testcred.cert \
        testcredlink \
        gridmap

testcred.key:
	umask 077; openssl genrsa 1024 > $@

testcred.req: testcred.key
	printf "NA\nNA\nNA\nNA\nNA\nNA\n\n\n\n" | openssl req -new -key $< > $@ -config openssl.cnf

testcred.cert: testcred.req testcred.key
	umask 077; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key > $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	cp testcred.cert "$$linkname"; \
        echo "$$linkname" > $@

gridmap: testcred.cert
	subject=`openssl x509 -subject -noout -in testcred.cert | sed -e 's/subject= *//'` ; \
        echo "\"$$subject\" `id -un`" > gridmap

if CYGPATH_W_DEFINED
X509_CERT_DIR = $$($(CYGPATH_W) $(abs_builddir))
GRIDMAP = $$($(CYGPATH_W) $(abs_builddir)/gridmap)
else
X509_CERT_DIR = $(abs_builddir)
GRIDMAP = $(abs_builddir)/gridmap
endif

TEST_PATH = $(GRIDFTP_SERVER_PATH):$(abs_top_builddir):$${PATH}
TESTS = $(check_SCRIPTS)
TESTS_ENVIRONMENT = \
    export X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_CERT_DIR=$(X509_CERT_DIR) \
    GRIDMAP=$(GRIDMAP) \
    PATH="$(TEST_PATH)";

LOG_COMPILER = $(LIBTOOL) --mode=execute \
    ${GSI_DRIVER_LIBS} \
    ${PIPE_DRIVER_LIBS} \
    $(srcdir)/test-wrapper

CLEANFILES = testcred.key testcred.cert testcred.req gridmap
clean-local:
	if [ -f testcredlink ]; then \
            rm -f "$$(cat testcredlink)" testcredlink; \
        fi
EXTRA_DIST = $(check_SCRIPTS) $(EXTRA_SCRIPTS) openssl.cnf
