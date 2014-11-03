check_SCRIPTS = globus-gram-job-manager-stdio-test.pl

check_DATA = \
    stdio001.err stdio001.out stdio001.rsl \
    stdio002.err stdio002.out stdio002.rsl \
    stdio003.err stdio003.out stdio003.rsl \
    stdio004.err stdio004.out stdio004.rsl \
    stdio005.err stdio005.out stdio005.rsl \
    stdio006.err stdio006.out stdio006.rsl \
    stdio007.err stdio007.out stdio007.rsl \
    stdio008.err stdio008.out stdio008.rsl \
    stdio009.err stdio009.out stdio009.rsl \
    stdio010.err stdio010.out stdio010.rsl \
    stdio011.err stdio011.out stdio011.rsl \
    stdio012.err stdio012.out stdio012.rsl \
    stdio013.err stdio013.out stdio013.rsl \
    stdio014.err stdio014.out stdio014.rsl \
    stdio015.err stdio015.out stdio015.rsl \
    stdio016.err stdio016.out stdio016.rsl \
    stdio017.err stdio017.out stdio017.rsl \
    stdio018.err stdio018.out stdio018.rsl \
    stdio019.err stdio019.out stdio019.rsl

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
TESTS = $(check_SCRIPTS)
EXTRA_DIST = $(check_SCRIPTS) $(check_DATA)
