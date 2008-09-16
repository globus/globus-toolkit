include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata records jobs perl_modules

pkgtestdir = $(GLOBUS_LOCATION)/test/$(PACKAGE)

Scripts = \
    TESTS.pl \
    globus-gram-job-manager-auditing-job-submission-test.pl \
    globus-gram-job-manager-auditing-upload-success-test.pl \
    globus-gram-job-manager-auditing-upload-failure-test.pl
    
pkgtest_SCRIPTS = $(Scripts)

pkgtest_DATA=

EXTRA_DIST = \
    TESTS.pl \
    globus-gram-job-manager-auditing-job-submission-test.pl \
    globus-gram-job-manager-auditing-upload-success-test.pl \
    globus-gram-job-manager-auditing-upload-failure-test.pl

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
