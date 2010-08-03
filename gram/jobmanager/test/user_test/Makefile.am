include $(top_srcdir)/globus_automake_pre

pkgtestdir = $(GLOBUS_LOCATION)/test/$(PACKAGE)
pkgdatadir = $(GLOBUS_LOCATION)/share/$(PACKAGE)

pkgtest_SCRIPTS = globus-gram-job-manager-user-test.pl

EXTRA_DIST = globus-gram-job-manager-user-test.pl.in
CLEANFILES = globus-gram-job-manager-user-test.pl
BUILT_SOURCES = globus-gram-job-manager-user-test.pl

globus-gram-job-manager-user-test.pl: $(srcdir)/globus-gram-job-manager-user-test.pl.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

include $(top_srcdir)/globus_automake_post
