include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata submit_test stdio_test failure_test proxy_expire_test \
        rsl_size_test user_test

pkgtestdir = $(GLOBUS_LOCATION)/test/$(PACKAGE)

Scripts = \
	TESTS.pl \
	globus-gram-job-manager-run-tests.pl

Data = \
	dc31a685.0 \
	dc31a685.signing_policy \
	testcred.pem

pkgtest_SCRIPTS = $(Scripts)

pkgtest_DATA=$(Data)

EXTRA_DIST = TESTS.pl globus-gram-job-manager-run-tests.pl.in $(Data)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
