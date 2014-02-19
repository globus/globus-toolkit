check_SCRIPTS = \
    grid-ca-create-test \
    grid-ca-sign-test

if RUN_TESTS
test_scripts = $(check_SCRIPTS)
endif

TESTS = $(test_scripts)

EXTRA_DIST = $(check_SCRIPTS)
TESTS_ENVIRONMENT=export PATH=$(abs_top_builddir):$(GLOBUS_COMMON_PATH):$${PATH};
