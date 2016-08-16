ACLOCAL_AMFLAGS=-I m4
pkgconfigdir = $(libdir)/pkgconfig

SUBDIRS = library test

doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-gsi-proxy-core.pc

EXTRA_DIST= \
	dirt.sh \
	$(doc_DATA)

distuninstallcheck:
	@:
