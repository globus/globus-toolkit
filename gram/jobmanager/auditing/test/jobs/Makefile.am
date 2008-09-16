include $(top_srcdir)/globus_automake_pre

pkgtestdir = $(GLOBUS_LOCATION)/test/$(PACKAGE)
pkgdatadir = $(GLOBUS_LOCATION)/test/$(PACKAGE)/jobs

pkgtest_SCRIPTS = 
pkgdata_DATA = \
    job-with-backticks.rsl.in \
    job-with-quotes.rsl.in \
    job-with-single-quotes.rsl.in

EXTRA_DIST = $(pkgdata_DATA)

include $(top_srcdir)/globus_automake_post
