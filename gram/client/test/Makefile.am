include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata

Scripts = \
	TESTS.pl \
	globus-gram-client-activate-test.pl \
	globus-gram-client-callback-contact-test.pl \
	globus-gram-client-cancel-test.pl \
	globus-gram-client-nonblocking-register-test.pl \
	globus-gram-client-ping-test.pl \
	globus-gram-client-refresh-credentials-test.pl \
	globus-gram-client-register-test.pl \
	globus-gram-client-register-callback-test.pl \
	globus-gram-client-register-cancel-test.pl \
	globus-gram-client-register-refresh-credentials-test.pl \
        globus-gram-client-set-credentials-test.pl \
	globus-gram-client-status-test.pl \
        globus-gram-client-stdio-size-test.pl \
        job-status-with-info-test.pl \
        local-stdio-size-test.pl \
        register-version-test.pl \
        restart-to-new-url-test.pl \
        stdio-update-test.pl \
        stdio-update-after-failure-test.pl \
        version-test.pl

Data = \
	dc31a685.0 \
	dc31a685.signing_policy \
	testcred.pem

test_DATA=$(Data)

test_SCRIPTS=$(Scripts) globus-gram-client-run-tests.pl globus-gram-client-two-phase-commit-test.pl globus-gram-client-register-ping-test.pl \
        failed-job-two-phase-commit.pl

test_PROGRAMS= \
        failed-job-two-phase-commit \
	globus-gram-client-activate-test \
	globus-gram-client-callback-contact-test \
	globus-gram-client-test \
	globus-gram-client-cancel-test \
	globus-gram-client-refresh-credentials-test \
	globus-gram-client-nonblocking-register-test \
	globus-gram-client-ping-test \
	globus-gram-client-register-callback-test \
	globus-gram-client-register-cancel-test \
	globus-gram-client-register-refresh-credentials-test \
	globus-gram-client-register-status-test \
        globus-gram-client-set-credentials-test \
	globus-gram-client-status-test \
        globus-gram-client-stdio-size-test \
	globus-gram-client-stdio-update-test \
	globus-gram-client-register-test \
	globus-gram-client-register-ping-test \
        globus-gram-client-two-phase-commit-test \
        job-status-with-info-test \
        register-version-test \
        restart-to-new-url-test \
        stdio-update-test \
        stdio-update-after-failure-test \
        local-stdio-size-test \
        version-test

EXTRA_DIST = $(Scripts) $(Data) globus-gram-client-run-tests.pl.in \
        globus-gram-client-two-phase-commit-test.pl.in \
	globus-gram-client-register-ping-test.pl.in \
        failed-job-two-phase-commit.pl.in \
	TESTS-junit.pl

junit: TESTS-junit.pl $(test_SCRIPTS) $(test_PROGRAMS)
	chmod +x $(test_SCRIPTS)
	PATH=${PATH}:. perl -I$(perlmoduledir) TESTS-junit.pl

INCLUDES = $(GPT_INCLUDES)

LDADD = $(GPT_PGM_LINKS)
failed_job_two_phase_commit_SOURCES = failed_job_two_phase_commit.c
failed_job_two_phase_commit_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_register_callback_test_SOURCES = globus_gram_client_register_callback_test.c
globus_gram_client_register_callback_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_activate_test_SOURCES = globus_gram_client_activate_test.c
globus_gram_client_activate_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_callback_contact_test_SOURCES = globus_gram_client_callback_contact_test.c
globus_gram_client_callback_contact_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_test_SOURCES = globus_gram_client_test.c
globus_gram_client_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_ping_test_SOURCES = globus_gram_client_ping_test.c
globus_gram_client_ping_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_nonblocking_register_test_SOURCES = \
    globus_gram_client_nonblocking_register_test.c
globus_gram_client_nonblocking_register_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_cancel_test_SOURCES = globus_gram_client_cancel_test.c
globus_gram_client_cancel_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_register_cancel_test_SOURCES = globus_gram_client_register_cancel_test.c
globus_gram_client_register_cancel_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_register_status_test_SOURCES = globus_gram_client_register_status_test.c
globus_gram_client_register_status_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_register_test_SOURCES = globus_gram_client_register_test.c
globus_gram_client_register_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_set_credentials_test_SOURCES = globus_gram_client_set_credentials_test.c
globus_gram_client_set_credentials_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_status_test_SOURCES = globus_gram_client_status_test.c
globus_gram_client_status_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_stdio_size_test_SOURCES = globus_gram_client_stdio_size_test.c
globus_gram_client_stdio_size_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_stdio_update_test_SOURCES = globus_gram_client_stdio_update_test.c
globus_gram_client_stdio_update_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_refresh_credentials_test_SOURCES = globus_gram_client_refresh_credentials_test.c
globus_gram_client_refresh_credentials_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_register_refresh_credentials_test_SOURCES = globus_gram_client_register_refresh_credentials_test.c
globus_gram_client_register_refresh_credentials_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_two_phase_commit_test_SOURCES = globus_gram_client_two_phase_commit_test.c
globus_gram_client_two_phase_commit_test_LDFLAGS = $(GPT_LDFLAGS)

globus_gram_client_register_ping_test_SOURCES = globus_gram_client_register_ping_test.c
globus_gram_client_register_ping_test_LDFLAGS = $(GPT_LDFLAGS)

register_version_test_SOURCES = register_version_test.c
register_version_test_LDFLAGS = $(GPT_LDFLAGS)

version_test_SOURCES = version_test.c
version_test_LDFLAGS = $(GPT_LDFLAGS)

job_status_with_info_test_SOURCES = job_status_with_info_test.c
job_status_with_info_test_LDFLAGS = $(GPT_LDFLAGS)

restart_to_new_url_test_SOURCES = restart_to_new_url_test.c
restart_to_new_url_test_LDFLAGS = $(GPT_LDFLAGS)

stdio_update_test_SOURCES = stdio_update_test.c
stdio_update_test_LDFLAGS = $(GPT_LDFLAGS)

stdio_update_after_failure_test_SOURCES = stdio_update_after_failure_test.c
stdio_update_after_failure_test_LDFLAGS = $(GPT_LDFLAGS)

local_stdio_size_test_SOURCES = local_stdio_size_test.c
local_stdio_size_test_LDFLAGS = $(GPT_LDFLAGS)

.PHONY: junit
include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
