include $(top_srcdir)/globus_automake_pre

pkgtestdir = $(GLOBUS_LOCATION)/test/$(PACKAGE)
pkgdatadir = $(GLOBUS_LOCATION)/share/$(PACKAGE)

pkgtest_SCRIPTS = globus-gram-job-manager-stdio-test.pl

pkgdata_DATA = \
    stdio001.err stdio001.out stdio001.rsl \
    stdio002.err stdio002.out stdio002.rsl \
    stdio003.err stdio003.out stdio003.rsl

EXTRA_DIST = globus-gram-job-manager-stdio-test.pl.in $(pkgdata_DATA)

include $(top_srcdir)/globus_automake_post
