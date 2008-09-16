include $(top_srcdir)/globus_automake_pre

pkgtestdir = $(GLOBUS_LOCATION)/test/$(PACKAGE)
pkgdatadir = $(GLOBUS_LOCATION)/test/$(PACKAGE)/records

pkgtest_SCRIPTS = 

pkgdata_DATA = \
    invalid-queued-timestamp.gramaudit.in \
    non-existing-username.gramaudit.in \
    too-few-fields.gramaudit.in \
    ok.gramaudit.in

EXTRA_DIST = $(pkgdata_DATA)

include $(top_srcdir)/globus_automake_post


