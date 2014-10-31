check_SCRIPTS = \
	failed-job-two-phase-commit.pl \
	nonblocking-register-test.pl \
	ping-test.pl \
	register-callback-test.pl \
	register-ping-test.pl \
	register-test.pl \
	two-phase-commit-test.pl

check_PROGRAMS = \
	failed-job-two-phase-commit \
	cancel-test \
	refresh-credentials-test \
	nonblocking-register-test \
	ping-test \
	register-callback-test \
	register-cancel-test \
	register-refresh-credentials-test \
	status-test \
	set-credentials-test \
	status-test \
	stdio-size-test \
	stdio-update-test \
	register-test \
	register-ping-test \
	two-phase-commit-test \
	job-status-with-info-test \
	register-version-test \
	restart-to-new-url-test \
	stdio-update-test \
	stdio-update-after-failure-test \
	local-stdio-size-test \
	version-test

TESTS = \
	cancel-test \
	failed-job-two-phase-commit.pl \
	nonblocking-register-test.pl \
	ping-test.pl \
	refresh-credentials-test \
	register-callback-test.pl \
	register-cancel-test \
	register-ping-test.pl \
	register-refresh-credentials-test \
	register-test.pl \
	status-test \
	two-phase-commit-test.pl \
	job-status-with-info-test \
	local-stdio-size-test \
	register-version-test \
	restart-to-new-url-test \
	set-credentials-test \
	stdio-size-test \
	stdio-update-after-failure-test \
	stdio-update-test \
	version-test

LDADD = $(GLOBUS_XIO_GSI_DRIVER_DLOPEN) $(PREOPEN_FORCE) $(CLIENT_TEST_PACKAGE_DEP_LIBS) -lltdl
AM_CPPFLAGS = $(CLIENT_TEST_PACKAGE_DEP_CFLAGS) -I$(top_srcdir)

if USE_CYGPATH_W
X509_USER_CERT = "$$($(CYGPATH_W) $(abs_top_builddir)/test/testcred.cert)"
X509_USER_KEY = "$$($(CYGPATH_W) $(abs_top_builddir)/test/testcred.key)"
X509_CERT_DIR = "$$($(CYGPATH_W) $(abs_top_builddir)/test)"
TEST_HOME_DIR = "$$($(CYGPATH_W) $(abs_top_builddir)/test)"
else
X509_USER_CERT = "$(abs_top_builddir)/test/testcred.cert"
X509_USER_KEY = "$(abs_top_builddir)/test/testcred.key"
X509_CERT_DIR = "$(abs_top_builddir)/test"
TEST_HOME_DIR = "$(abs_top_builddir)/test"
endif

TESTS_ENVIRONMENT = export \
    X509_USER_CERT=$(X509_USER_CERT) \
    X509_USER_KEY=$(X509_USER_KEY) \
    X509_CERT_DIR=$(X509_CERT_DIR) \
    HOME=$(TEST_HOME_DIR);
LOG_COMPILER = $(LIBTOOL) --mode=execute \
    $(GLOBUS_XIO_GSI_DRIVER_DLOPEN) \
    $(GLOBUS_XIO_POPEN_DRIVER_DLOPEN) \
    ../gram-test-wrapper

EXTRA_DIST = $(check_SCRIPTS)
