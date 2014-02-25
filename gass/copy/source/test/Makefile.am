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
	umask 077; openssl genrsa -out $@ 1024

testcred.req: testcred.key
	printf "NA\nNA\nNA\nNA\nNA\n$$(openssl rand -base64 6)\n\n\n\n" | openssl req -new -key $< -out $@

testcred.cert: testcred.req testcred.key
	umask 077; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key -out $@

testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	ln -s testcred.cert "$$linkname"; \
        echo "$$linkname" > $@

gridmap: testcred.cert
	subject=`openssl x509 -subject -noout -in testcred.cert | sed -e 's/subject= *//'` ; \
        echo "\"$$subject\" `id -un`" > gridmap

TESTS = $(check_SCRIPTS)
TESTS_ENVIRONMENT = \
    export X509_USER_CERT=$(abs_builddir)/testcred.cert \
    X509_USER_KEY=$(abs_builddir)/testcred.key \
    X509_CERT_DIR=$(abs_builddir) \
    GRIDMAP=$(abs_builddir)/gridmap \
    PATH="$(GRIDFTP_SBINDIR):$(abs_top_builddir):$${PATH}"; \
    for ext in .la .so .dylib .a; do \
	driver="$(GSI_DRIVER_LIBDIR)/libglobus_xio_gsi_driver$${ext}"; \
	if test -r "$${driver}"; then \
	    export GSI_DRIVER_LOAD="-dlopen $${driver}"; \
	    break; \
	fi; \
    done; \
    for ext in .la .so .dylib .a; do \
	driver="$(PIPE_DRIVER_LIBDIR)/libglobus_xio_pipe_driver$${ext}"; \
	if test -r "$${driver}"; then \
	    export PIPE_DRIVER_LOAD="-dlopen $${driver}"; \
	    break; \
	fi; \
    done;
    

LOG_COMPILER = $(LIBTOOL) --mode=execute \
    $${GSI_DRIVER_LOAD} \
    $${PIPE_DRIVER_LOAD} \
    $(srcdir)/test-wrapper

CLEANFILES = testcred.key testcred.cert testcred.req gridmap
clean-local:
	if [ -f testcredlink ]; then \
            rm -f "$$(cat testcredlink)" testcredlink; \
        fi
EXTRA_DIST = $(check_SCRIPTS) $(EXTRA_SCRIPTS)
