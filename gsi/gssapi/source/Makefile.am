ACLOCAL_AMFLAGS=-I m4
SUBDIRS = library . test

pkgconfigdir = $(libdir)/pkgconfig

doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-gssapi-gsi.pc

EXTRA_DIST = \
	dirt.sh \
	$(doc_DATA)

distuninstallcheck:
	@:
