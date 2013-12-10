pkgconfigdir = $(libdir)/pkgconfig

SUBDIRS = library programs

doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-gsi-cert-utils.pc

EXTRA_DIST = \
        version.h \
        dirt.sh \
	$(doc_DATA)

distuninstallcheck:
	@:
