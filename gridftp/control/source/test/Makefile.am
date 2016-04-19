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

if CYGPATH_W_DEFINED
X509_CERT_DIR = $$($(CYGPATH_W) $(abs_builddir))
GRIDMAP = $$($(CYGPATH_W) $(abs_builddir)/testcredgridmap)
else
X509_CERT_DIR = $(abs_builddir)
GRIDMAP = $(abs_builddir)/testcredgridmap
endif

TESTS_ENVIRONMENT = export \
    X509_USER_CERT=testcred.cert \
    X509_USER_KEY=testcred.key \
    X509_CERT_DIR=$(X509_CERT_DIR) \
    GRIDMAP=$(GRIDMAP) \
    PATH=$${PATH}:$(abs_builddir):$(abs_srcdir);
LOG_COMPILER = $(LIBTOOL) --mode=execute $(GSI_DRIVER_DLOPEN)

testcred.key:
	umask 077 ; openssl genrsa 1024 > $@

.key.req:
	printf "NA\nNA\nNA\nNA\nNA\nNA\nNA\n\n\n\n" | openssl req -new -key $< -config openssl.cnf > $@

.req.cert:
	umask 022; openssl x509 -req -days 365 -in testcred.req -signkey testcred.key > $@

testcredgridmap: testcred.cert
	@subject=`openssl x509 -subject -in $< -noout | sed -e 's/subject= //'`; \
	umask 022; echo "\"$$subject\" `id -un`" > $@
	
testcredlink: testcred.cert
	linkname="`openssl x509 -hash -noout -in testcred.cert`.0"; \
	rm -f "$$linkname"; \
	cp testcred.cert "$$linkname" ; \
	echo "$$linkname" > $@

AM_CPPFLAGS = -I$(top_srcdir) $(PACKAGE_DEP_CFLAGS)
test_ldadd = $(GSI_DRIVER_DLPREOPEN) libtest_common.la ../libglobus_ftp_control.la $(PACKAGE_DEP_LIBS) -lltdl
test_ldflags = -dlpreopen force

check_LTLIBRARIES = libtest_common.la
libtest_common_la_SOURCES = connect_disconnect_test.c test_common.c test_common.h
libtest_common_la_LIBADD = ../libglobus_ftp_control.la $(PACKAGE_DEP_LIBS)

data_test_SOURCES = data_test.c
data_test_LDADD = $(test_ldadd)
data_test_LDFLAGS = $(test_ldflags)

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
get_lingering_close_LDFLAGS = $(test_ldflags)

globus_ftp_control_test_LDADD = $(test_ldadd)
globus_ftp_control_test_LDFLAGS = $(test_ldflags)

pipe_test_LDADD = $(test_ldadd)
pipe_test_LDFLAGS = $(test_ldflags)

test_server_LDADD = $(test_ldadd)
test_server_LDFLAGS = $(test_ldflags)

CLEANFILES = testcredgridmap testcred.cert testcred.key testcred.req get_lingering_close.sh.port
clean-local:
	if [ -f testcredlink ]; then \
            rm -f $$(cat testcredlink) testcredlink; \
        fi
EXTRA_DIST = $(check_SCRIPTS)
SUFFIXES = .key .req .cert
