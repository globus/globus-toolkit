include $(top_srcdir)/aclocal/automake_targets

sbin_SCRIPTS = \
	libtool-$(GLOBUS_FLAVOR_NAME)

flavorincludedir = $(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOR_NAME)

flavorinclude_HEADERS = \
	globus_config.h

SUBDIRS = aclocal config scripts pkgdata doxygen


EXTRA_DIST = bootstrap

dist-hook:
	$(GPT_LOCATION)/sbin/gpt_create_automake_rules -srcdir=$(top_distdir)

$(srcdir)/Makefile.in: Makefile.am $(top_srcdir)/configure.in $(ACLOCAL_M4)
	cd $(top_srcdir) && $(AUTOMAKE) --foreign Makefile && $(GPT_LOCATION)/sbin/gpt_create_automake_rules
