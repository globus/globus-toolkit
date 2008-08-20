include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata

pkgtestdir = $(GLOBUS_LOCATION)/test/$(PACKAGE)

pkgtest_SCRIPTS = \
        TESTS.pl \
        grid-proxy-utils-test.pl

EXTRA_DIST = $(pkgtest_SCRIPTS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
