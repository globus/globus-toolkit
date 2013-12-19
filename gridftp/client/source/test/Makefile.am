EXTRA_SCRIPTS = TESTS.pl TESTS-junit.pl run-tests.pl many-server.pl run-backend-tests.pl test-wrapper

check_SCRIPTS = \
	dir-test.pl \
	bad-buffer-test.pl \
	create-destroy-test.pl \
	exist-test.pl \
	extended-get-test.pl \
	extended-put-test.pl \
	extended-transfer-test.pl \
	lingering-get-test.pl \
	multiple-block-get-test.pl \
	partial-get-test.pl \
	partial-put-test.pl \
	partial-transfer-test.pl \
	plugin-test.pl \
	get-test.pl \
	caching-get-test.pl \
	put-test.pl \
	size-test.pl \
	transfer-test.pl \
	caching-transfer-test.pl \
	caching-extended-get-test.pl \
	user-auth-test.pl

check_DATA_real = \
	FtpTestLib.pm \
        URL.pm
check_DATA = $(check_DATA_real) \
        testcred.key \
        testcred.cert \
        testcredlink \
        gridmap

check_LTLIBRARIES = libglobus_ftp_client_test.la

check_PROGRAMS = \
	ascii-list-test \
	ascii-verbose-list-test \
	ascii-machine-list-test \
	ascii-recursive-list-test \
	bad-buffer-test \
	cache-all-test \
	create-destroy-test \
	cksm-test \
	chmod-test \
	chgrp-test \
	utime-test \
	symlink-test \
	delete-test \
	exist-test \
	extended-get-test \
	extended-get-caching-test \
	extended-put-test \
	extended-transfer-test \
	feat-test \
	lingering-get-test \
	mlst-test \
	mkdir-test \
	modification-time-test \
	move-test \
	multiget-test \
	multiple-bad-buffer-test \
	multiple-block-get-test \
	multiple-block-put-test \
	partial-get-test \
	partial-put-test \
	partial-read-all-test \
	partial-transfer-test \
	plugin-test \
	read-all-test \
	rmdir-test \
	size-test \
	get-test \
	caching-get-test \
	put-test \
	transfer-test \
	caching-transfer-test \
	pipelined-transfer-test \
	user-auth-test \
        restart-marker-test

TESTS = $(check_SCRIPTS)
AM_CPPFLAGS = -I$(top_srcdir) $(PACKAGE_DEP_CFLAGS)
LDADD = libglobus_ftp_client_test.la $(top_builddir)/libglobus_ftp_client.la $(PACKAGE_DEP_LIBS)


AM_TESTS_ENVIRONMENT = \
    export X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_CERT_DIR=$(abs_builddir) \
    GRIDMAP=$(abs_builddir)/gridmap;
LOG_COMPILER = $(srcdir)/test-wrapper

libglobus_ftp_client_test_la_SOURCES = \
	globus_ftp_client_test_abort_plugin.h \
	globus_ftp_client_test_pause_plugin.h \
	globus_ftp_client_test_restart_plugin.h \
	globus_ftp_client_test_perf_plugin.h \
	globus_ftp_client_test_throughput_plugin.h \
	globus_ftp_client_test_common.h \
	globus_ftp_client_test_abort_plugin.c \
	globus_ftp_client_test_pause_plugin.c \
	globus_ftp_client_test_restart_plugin.c \
	globus_ftp_client_test_perf_plugin.c \
	globus_ftp_client_test_throughput_plugin.c \
	globus_ftp_client_test_common.c
libglobus_ftp_client_test_la_LDFLAGS = $(top_builddir)/libglobus_ftp_client.la $(PACKAGE_DEP_LIBS) -rpath $(abs_builddir) -no-undefined

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

test: $(test_SCRIPTS)
	chmod a+x $(test_SCRIPTS)
	perl ./TESTS.pl

junit: $(test_SCRIPTS)
	chmod a+x $(test_SCRIPTS)
	perl ./TESTS-junit.pl

CLEANFILES = testcred.key testcred.cert testcred.req

EXTRA_DIST = \
        dirt.sh \
        $(check_DATA_real) \
        $(globusperl_DATA) \
	TESTS.pl \
        TESTS-junit.pl \
	FtpTestLib.pm \
        $(check_SCRIPTS) \
	$(EXTRA_SCRIPTS)

.PHONY: test junit testcredlink
