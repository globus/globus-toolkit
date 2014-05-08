SUBDIRS = . submit_test stdio_test failure_test rsl_size_test user_test

check_SCRIPTS = job-manager-script-test.pl
TESTS = $(check_SCRIPTS)

if USE_CYGPATH_W
X509_USER_CERT = "$$($(CYGPATH_W) $(abs_top_builddir)/testcred.cert)"
X509_USER_KEY = "$$($(CYGPATH_W) $(abs_top_builddir)/testcred.key)"
X509_CERT_DIR = "$$($(CYGPATH_W) $(abs_top_builddir)"
else
X509_USER_CERT = "$(abs_top_builddir)/testcred.cert"
X509_USER_KEY = "$(abs_top_builddir)/testcred.key"
X509_CERT_DIR = "$(abs_top_builddir)"
endif

TESTS_ENVIRONMENT = export \
    X509_USER_CERT=$(X509_USER_CERT) \
    X509_USER_KEY=$(X509_USER_KEY) \
    X509_CERT_DIR=$(X509_CERT_DIR) ;
LOG_COMPILER = $(abs_top_builddir)/test/gram-test-wrapper

EXTRA_DIST = $(check_SCRIPTS)
