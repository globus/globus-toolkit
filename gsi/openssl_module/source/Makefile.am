ACLOCAL_AMFLAGS=-I m4
pkgconfigdir = $(libdir)/pkgconfig

SUBDIRS = library
doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-openssl-module.pc

EXTRA_DIST = \
	dirt.sh \
	$(doc_DATA)

distuninstallcheck:
	@:
