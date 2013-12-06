include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata

pkgtestdir = $(GLOBUS_LOCATION)/test/$(PACKAGE)

pkgtest_SCRIPTS = \
        TESTS.pl \
        TESTS-junit.pl \
        grid-proxy-utils-test.pl \
        proxy-order-test.pl

pkgtest_DATA = \
        b38b4d8c.0 b38b4d8c.signing_policy \
        usercert.pem userkey.pem

EXTRA_DIST = TESTS.pl.in TESTS-junit.pl grid-proxy-utils-test.pl \
	proxy-order-test.pl \
        $(pkgtest_DATA)

test:
	chmod a+x $(pkgtest_SCRIPTS)
	perl ./TESTS.pl

junit:
	chmod a+x $(pkgtest_SCRIPTS)
	perl ./TESTS-junit.pl

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
