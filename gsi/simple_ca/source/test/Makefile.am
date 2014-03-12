check_SCRIPTS = \
    grid-ca-create-test \
    grid-ca-sign-test

test_scripts = $(check_SCRIPTS)

TESTS = $(test_scripts)
if !RUN_TESTS
XFAIL_TESTS = $(test_scripts)
endif

TEST_PATH=$(abs_top_builddir):$(GLOBUS_COMMON_PATH):$${PATH}

EXTRA_DIST = $(check_SCRIPTS)
TESTS_ENVIRONMENT=export PATH=$(TEST_PATH);
