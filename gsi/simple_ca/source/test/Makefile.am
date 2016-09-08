check_SCRIPTS = \
    grid-ca-create-test \
    grid-ca-sign-test

test_scripts = $(check_SCRIPTS)

TESTS = $(test_scripts)

TEST_PATH = $(abs_top_builddir):$(GLOBUS_COMMON_PATH):$${PATH}

EXTRA_DIST = $(check_SCRIPTS)
TESTS_ENVIRONMENT = export \
    PATH=$(TEST_PATH) \
    OPENSSL=$(OPENSSL) \
    RANDFILE=$(abs_top_builddir)/test/.rnd;

CLEANFILES = .rnd
