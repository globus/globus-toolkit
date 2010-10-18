include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata records jobs perl_modules

pkgtestdir = $(GLOBUS_LOCATION)/test/$(PACKAGE)

Scripts = \
    TESTS.pl \
    globus-gram-job-manager-auditing-upload-success-test.pl \
    globus-gram-job-manager-auditing-upload-failure-test.pl

GeneratedScripts = \
    globus-gram-job-manager-auditing-tg-job-submission-test.pl \
    globus-gram-job-manager-auditing-job-submission-test.pl

GeneratedScriptsSources = \
    globus-gram-job-manager-auditing-tg-job-submission-test.pl.in \
    globus-gram-job-manager-auditing-job-submission-test.pl.in

pkgtest_SCRIPTS = $(Scripts) $(GeneratedScripts)

pkgtest_DATA=testcert.pem testkey.pem \
             b38b4d8c.0 b38b4d8c.signing_policy bootstrap \
             testproxy.pem shibproxy.pem

EXTRA_DIST = $(Scripts) $(GeneratedScriptsSources) $(pkgtest_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
