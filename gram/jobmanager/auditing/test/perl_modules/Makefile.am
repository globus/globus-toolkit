include $(top_srcdir)/globus_automake_pre

pkgtestdir = $(GLOBUS_LOCATION)/test/$(PACKAGE)
pkgdatadir = $(GLOBUS_LOCATION)/test/$(PACKAGE)/perl_modules

pkgtest_SCRIPTS = 

pkgdata_DATA= \
    ConfigurationManager.pm \
    GatekeeperManager.pm \
    Uploader.pm \
    Util.pm

EXTRA_DIST = GatekeeperManager.pm Util.pm \
             ConfigurationManager.pm.in Uploader.pm.in

BUILT_SOURCES = ConfigurationManager.pm Uploader.pm
ConfigurationManager.pm: $(srcdir)/ConfigurationManager.pm.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
Uploader.pm: $(srcdir)/Uploader.pm.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

CLEANFILES = ConfigurationManager.pm Uploader.pm

include $(top_srcdir)/globus_automake_post
