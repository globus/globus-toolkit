include $(top_srcdir)/aclocal/automake_targets

licensedir = $(GLOBUS_LOCATION)
## license = [ DATA ]

license_DATA = GLOBUS_LICENSE

sbin_SCRIPTS = \
	libtool-$(GLOBUS_FLAVOR_NAME)

flavorinclude_HEADERS = \
	globus_config.h

SUBDIRS = aclocal config scripts pkgdata doxygen


EXTRA_DIST = bootstrap GLOBUS_LICENSE dirt.sh

dist-hook:
	$(GPT_LOCATION)/sbin/gpt_create_automake_rules -srcdir=$(top_distdir)

distclean-local:
	@if test -f libtool-$(GLOBUS_FLAVOR_NAME); then \
		rm libtool-$(GLOBUS_FLAVOR_NAME); \
	fi
