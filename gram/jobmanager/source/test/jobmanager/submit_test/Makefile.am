check_SCRIPTS = globus-gram-job-manager-submit-test.pl

check_DATA = \
    submit001.err submit001.out submit001.rsl \
    submit002.err submit002.out submit002.rsl \
    submit003.err submit003.out submit003.rsl \
    submit004.err submit004.out submit004.rsl \
    submit005.err submit005.out submit005.rsl \
    submit006.err submit006.out submit006.rsl \
    submit007.err submit007.out submit007.rsl \
    submit008.err submit008.out submit008.rsl \
    submit009.err submit009.out submit009.rsl \
    submit010.err submit010.out submit010.rsl \
    submit011.err submit011.out submit011.rsl \
    submit012.err submit012.out submit012.rsl \
    submit013.err submit013.out submit013.rsl \
    submit014.err submit014.out submit014.rsl \
    submit015.err submit015.out submit015.rsl \
    submit016.err submit016.out submit016.rsl \
    submit017.err submit017.out submit017.rsl \
    submit018.err submit018.out submit018.rsl \
    submit019.err submit019.out submit019.rsl \
    submit020.err submit020.out submit020.rsl \
    submit021.err submit021.out submit021.rsl \
    submit022.err submit022.out submit022.rsl \
    submit023.err submit023.out submit023.rsl \
    submit024.err submit024.out submit024.rsl \
    submit025.err submit025.out submit025.rsl \
    submit026.err submit026.out submit026.rsl \
    submit027.err submit027.out submit027.rsl \
    submit028.err submit028.out submit028.rsl \
    submit029.err submit029.out submit029.rsl \
    submit030.err submit030.out submit030.rsl \
    submit031.err submit031.out submit031.rsl \
    submit032.err submit032.out submit032.rsl \
    submit033.err submit033.out submit033.rsl \
    submit034.err submit034.out submit034.rsl \
    submit035.err submit035.out submit035.rsl \
    submit036.err submit036.out submit036.rsl \
    submit037.err submit037.out submit037.rsl \
    submit038.err submit038.out submit038.rsl \
    submit039.err submit039.out submit039.rsl \
    submit040.err submit040.out submit040.rsl \
    submit041.err submit041.out submit041.rsl \
    submit042.err submit042.out submit042.rsl \
    submit043.err submit043.out submit043.rsl \
    submit044.err submit044.out submit044.rsl \
    submit045.err submit045.out submit045.rsl \
    submit046.err submit046.out submit046.rsl \
    submit047.err submit047.out submit047.rsl \
    submit048.err submit048.out submit048.rsl \
    submit049.err submit049.out submit049.rsl

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
EXTRA_DIST = $(check_DATA)
