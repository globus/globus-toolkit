ACLOCAL_AMFLAGS=-I m4
SUBDIRS = library

pkgconfigdir = $(libdir)/pkgconfig

doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-gsi-credential.pc

EXTRA_DIST= \
	dirt.sh \
	$(doc_DATA)

distuninstallcheck:
	@:
