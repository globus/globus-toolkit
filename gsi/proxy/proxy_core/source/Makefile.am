pkgconfigdir = $(libdir)/pkgconfig

SUBDIRS = library

doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-gsi-proxy-core.pc

EXTRA_DIST= \
        version.h \
        dirt.sh \
	$(doc_DATA)

distuninstallcheck:
	@:
