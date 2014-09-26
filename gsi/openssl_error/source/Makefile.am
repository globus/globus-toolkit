ACLOCAL_AMFLAGS=-I m4
pkgconfdir = $(libdir)/pkgconfig

SUBDIRS = library test

doc_DATA = GLOBUS_LICENSE
pkgconf_DATA = globus-gsi-openssl-error.pc

EXTRA_DIST= \
	dirt.sh \
	$(doc_DATA)

distuninstallcheck:
	@:
