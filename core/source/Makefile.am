include $(top_srcdir)/aclocal/automake_targets

sbin_SCRIPTS = \
	libtool-$(GLOBUS_FLAVOR_NAME)

flavorincludedir = $(GLOBUS_INSTALL_PATH)/include/$(GLOBUS_FLAVOR_NAME)

flavorinclude_HEADERS = \
	globus_config.h

SUBDIRS = aclocal config scripts tests pkgdata

EXTRA_DIST = bootstrap

include $(top_srcdir)/aclocal/automake_rules
include $(top_srcdir)/aclocal/automake_top_rules
