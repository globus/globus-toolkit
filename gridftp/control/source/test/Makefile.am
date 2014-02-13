check_PROGRAMS = \
    data_test \
    get_lingering_close \
    globus_ftp_control_test \
    pipe_test \
    test_server

check_SCRIPTS = get_lingering_close.sh

check_DATA = \
        testcred.key \
        testcred.cert \
        testcredlink \
        testcredgridmap

TESTS = \
    data_test \
    pipe_test \
    $(check_SCRIPTS)

TESTS_ENVIRONMENT = export \
    X509_USER_CERT=$(abs_builddir)/testcred.cert \
    X509_USER_KEY=$(abs_builddir)/testcred.key \
    X509_CERT_DIR=$(abs_builddir) \
    GRIDMAP=$(abs_builddir)/testcredgridmap \
    PATH=$${PATH}:$(abs_builddir):$(abs_srcdir);

testcred.key:
	umask 077 ; openssl genrsa -out $@ 1024

testcred.req: testcred.key
	printf "NA\nNA\nNA\nNA\nNA\nNA\n$$(openssl rand -base64 6)\n\n\n\n" | openssl req -new -key $< -out $@

testcred.cert: testcred.req testcred.key
	umask 022; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key -out $@

testcredgridmap: testcred.cert
	@subject=`openssl x509 -subject -in $< -noout | sed -e 's/subject= //'`; \
	umask 022; echo "\"$$subject\" `id -un`" > $@
	
testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	ln -s testcred.cert "$$linkname" ; \
	echo "$$linkname" > $@

AM_CPPFLAGS = -I$(top_srcdir) $(PACKAGE_DEP_CFLAGS)
test_ldadd = libtest_common.la ../libglobus_ftp_control.la $(PACKAGE_DEP_LIBS)

check_LTLIBRARIES = libtest_common.la
libtest_common_la_SOURCES = connect_disconnect_test.c test_common.c test_common.h
libtest_common_la_LIBADD = ../libglobus_ftp_control.la $(PACKAGE_DEP_LIBS)

data_test_SOURCES = data_test.c
data_test_LDADD = $(test_ldadd)

globus_ftp_control_test_SOURCES = \
    abort_test.c \
    async_control_test.c \
    globus_ftp_control_test.c \
    globus_ftp_control_test.h \
    eb_simple_data_test.c \
    outstanding_io_test.c \
    simple_control_test.c \
    simple_data_test.c \
    simple_dir_test.c 

get_lingering_close_LDADD = $(test_ldadd)
globus_ftp_control_test_LDADD = $(test_ldadd)
pipe_test_LDADD = $(test_ldadd)
test_server_LDADD = $(test_ldadd)

CLEANFILES = testcredgridmap testcred.cert testcred.key testcred.req get_lingering_close.sh.port
clean-local:
	if [ -f testcredlink ]; then \
            rm -f $$(cat testcredlink) testcredlink; \
        fi
EXTRA_DIST = $(check_SCRIPTS)
