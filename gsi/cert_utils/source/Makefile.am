ACLOCAL_AMFLAGS=-I m4
pkgconfigdir = $(libdir)/pkgconfig

SUBDIRS = library programs test

doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-gsi-cert-utils.pc

EXTRA_DIST = \
	dirt.sh \
	$(doc_DATA)

distuninstallcheck:
	@:
