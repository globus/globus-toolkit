include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata

pkgtestdir = $(GLOBUS_LOCATION)/test/$(PACKAGE)

Scripts = \
	TESTS.pl \
	globus-gram-job-manager-run-auditing-test.pl

Data = \
	dc31a685.0 \
	dc31a685.signing_policy \
	testcred.pem \
	Readme.txt

pkgtest_SCRIPTS = $(Scripts)

pkgtest_DATA=$(Data)

EXTRA_DIST = \
	TESTS.pl \
	globus-gram-job-manager-run-auditing-test.pl \
	$(Data)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
