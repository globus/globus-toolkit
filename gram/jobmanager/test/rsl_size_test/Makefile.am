include $(top_srcdir)/globus_automake_pre

pkgtestdir = $(GLOBUS_LOCATION)/test/$(PACKAGE)
pkgdatadir = $(GLOBUS_LOCATION)/share/$(PACKAGE)

pkgtest_SCRIPTS = globus-gram-job-manager-rsl-size-test.pl

pkgdata_DATA = \
        tiny.err tiny.out tiny.rc tiny.rsl \
        small.err small.out small.rc small.rsl \
        medium.err medium.out medium.rc medium.rsl \
        large.err large.out large.rc large.rsl \
        huge.err huge.out huge.rc huge.rsl

EXTRA_DIST = globus-gram-job-manager-rsl-size-test.pl.in $(pkgdata_DATA)

BUILT_SOURCES = globus-gram-job-manager-rsl-size-test.pl
CLEANFILES = globus-gram-job-manager-rsl-size-test.pl

globus-gram-job-manager-rsl-size-test.pl: $(srcdir)/globus-gram-job-manager-rsl-size-test.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

include $(top_srcdir)/globus_automake_post
