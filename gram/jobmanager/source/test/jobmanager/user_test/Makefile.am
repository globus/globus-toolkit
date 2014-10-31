check_SCRIPTS = globus-gram-job-manager-user-test.pl

TESTS = $(check_SCRIPTS)

if USE_CYGPATH_W
X509_USER_CERT = "$$($(CYGPATH_W) $(abs_top_builddir)/test/testcred.cert)"
X509_USER_KEY = "$$($(CYGPATH_W) $(abs_top_builddir)/test/testcred.key)"
X509_CERT_DIR = "$$($(CYGPATH_W) $(abs_top_builddir)/test)"
TEST_DATA_DIR = "$$($(CYGPATH_W) $(abs_srcdir))"
TEST_HOME_DIR = "$$($(CYGPATH_W) $(abs_top_builddir)/test)"
else
X509_USER_CERT = "$(abs_top_builddir)/test/testcred.cert"
X509_USER_KEY = "$(abs_top_builddir)/test/testcred.key"
X509_CERT_DIR = "$(abs_top_builddir)/test"
TEST_DATA_DIR = "$(abs_srcdir)"
TEST_HOME_DIR = "$(abs_top_builddir)/test"
endif

TESTS_ENVIRONMENT = export \
    X509_USER_CERT=$(X509_USER_CERT) \
    X509_USER_KEY=$(X509_USER_KEY) \
    X509_CERT_DIR=$(X509_CERT_DIR) \
    TEST_DATA_DIR=$(TEST_DATA_DIR) \
    HOME=$(TEST_HOME_DIR);
LOG_COMPILER = $(LIBTOOL) --mode=execute \
    $(GLOBUS_XIO_GSI_DRIVER_DLOPEN) \
    $(GLOBUS_XIO_POPEN_DRIVER_DLOPEN) \
    ../../gram-test-wrapper
EXTRA_DIST = $(check_SCRIPTS)
