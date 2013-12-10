ACLOCAL_AMFLAGS = -I config -I .

pkgconfdir = ${libdir}/pkgconfig

SUBDIRS = \
	library \
	programs \
	scripts \
        manpages \
        test

doc_DATA = GLOBUS_LICENSE

pkgconf_DATA = globus-common.pc
libexec_SCRIPTS = build-aux/config.guess

EXTRA_DIST = \
	dirt.sh \
	version.h.in \
	globus_common.txt \
	$(doc_DATA)

distuninstallcheck:
	@:
