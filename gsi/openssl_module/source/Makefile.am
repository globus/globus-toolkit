pkgconfigdir = $(libdir)/pkgconfig

SUBDIRS = library
doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-openssl-module.pc

EXTRA_DIST = \
	dirt.sh \
	version.h.in \
	$(doc_DATA)

distuninstallcheck:
	@:
