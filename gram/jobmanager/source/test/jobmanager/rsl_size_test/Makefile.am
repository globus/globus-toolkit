check_SCRIPTS = globus-gram-job-manager-rsl-size-test.pl

check_DATA = \
        tiny.err tiny.out tiny.rc tiny.rsl \
        small.err small.out small.rc small.rsl \
        medium.err medium.out medium.rc medium.rsl \
        large.err large.out large.rc large.rsl \
        huge.err huge.out huge.rc huge.rsl

TESTS = $(check_SCRIPTS)

if USE_CYGPATH_W
X509_USER_CERT = "$$($(CYGPATH_W) $(abs_top_builddir)/test/testcred.cert)"
X509_USER_KEY = "$$($(CYGPATH_W) $(abs_top_builddir)/test/testcred.key)"
X509_CERT_DIR = "$$($(CYGPATH_W) $(abs_top_builddir)/test)"
TEST_DATA_DIR = "$$($(CYGPATH_W) $(abs_srcdir))"
else
X509_USER_CERT = "$(abs_top_builddir)/test/testcred.cert"
X509_USER_KEY = "$(abs_top_builddir)/test/testcred.key"
X509_CERT_DIR = "$(abs_top_builddir)/test"
TEST_DATA_DIR = "$(abs_srcdir)"
endif

TESTS_ENVIRONMENT = export \
    X509_USER_CERT=$(X509_USER_CERT) \
    X509_USER_KEY=$(X509_USER_KEY) \
    X509_CERT_DIR=$(X509_CERT_DIR) \
    TEST_DATA_DIR=$(TEST_DATA_DIR);
LOG_COMPILER = $(LIBTOOL) --mode=execute \
    $(GLOBUS_XIO_GSI_DRIVER_DLOPEN) \
    $(GLOBUS_XIO_POPEN_DRIVER_DLOPEN) \
    ../../gram-test-wrapper

EXTRA_DIST = $(check_SCRIPTS) $(check_DATA)
