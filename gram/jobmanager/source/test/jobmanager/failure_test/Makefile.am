check_SCRIPTS = globus-gram-job-manager-failure-test.pl

check_DATA = \
    error_bad_directory.rsl \
    error_evaluation_failed.rsl \
    error_executable_not_found.rsl \
    error_executable_permissions.rsl \
    error_invalid_cache2.rsl \
    error_invalid_cache.rsl \
    error_invalid_count.rsl \
    error_invalid_file_cleanup.rsl \
    error_invalid_gram_myjob.rsl \
    error_invalid_host_count2.rsl \
    error_invalid_host_count.rsl \
    error_invalid_jobtype.rsl \
    error_invalid_max_cpu_time.rsl \
    error_invalid_max_memory.rsl \
    error_invalid_maxtime.rsl \
    error_invalid_max_wall_time.rsl \
    error_invalid_min_memory.rsl \
    error_invalid_proxy_timeout.rsl \
    error_invalid_project.rsl \
    error_invalid_queue.rsl \
    error_invalid_save_state.rsl \
    error_invalid_scratch.rsl \
    error_invalid_two_phase_commit.rsl \
    error_no_state_file.rsl \
    error_opening_stderr2.rsl \
    error_opening_stderr.rsl \
    error_opening_stdout2.rsl \
    error_opening_stdout3.rsl \
    error_opening_stdout.rsl \
    error_rsl_arguments.rsl \
    error_rsl_cache.rsl \
    error_rsl_directory.rsl \
    error_rsl_dryrun.rsl \
    error_rsl_environment1.rsl \
    error_rsl_environment2.rsl \
    error_rsl_evaluation_failed2.rsl \
    error_rsl_evaluation_failed.rsl \
    error_rsl_executable.rsl \
    error_rsl_file_stage_in2.rsl \
    error_rsl_file_stage_in3.rsl \
    error_rsl_file_stage_in.rsl \
    error_rsl_file_stage_in_shared2.rsl \
    error_rsl_file_stage_in_shared3.rsl \
    error_rsl_file_stage_in_shared.rsl \
    error_rsl_file_stage_out2.rsl \
    error_rsl_file_stage_out3.rsl \
    error_rsl_file_stage_out.rsl \
    error_rsl_host_count.rsl \
    error_rsl_jobtype.rsl \
    error_rsl_max_cpu_time.rsl \
    error_rsl_max_memory.rsl \
    error_rsl_maxtime.rsl \
    error_rsl_max_wall_time.rsl \
    error_rsl_min_memory.rsl \
    error_rsl_myjob.rsl \
    error_rsl_project.rsl \
    error_rsl_proxy_timeout.rsl \
    error_rsl_queue.rsl \
    error_rsl_remote_io_url.rsl \
    error_rsl_restart.rsl \
    error_rsl_save_state.rsl \
    error_rsl_scratch.rsl \
    error_rsl_stderr2.rsl \
    error_rsl_stderr.rsl \
    error_rsl_stdin.rsl \
    error_rsl_stdout2.rsl \
    error_rsl_stdout.rsl \
    error_rsl_two_phase_commit.rsl \
    error_staging_executable.rsl \
    error_staging_stdin.rsl \
    error_stdin_not_found.rsl \
    error_undefined_executable.rsl

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
EXTRA_DIST = $(check_DATA)
