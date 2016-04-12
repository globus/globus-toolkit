ACLOCAL_AMFLAGS = -I m4

pkgconfdir = ${libdir}/pkgconfig

SUBDIRS = \
	library \
	programs \
	scripts \
        manpages \
        test

doc_DATA = GLOBUS_LICENSE

pkgconf_DATA = globus-common.pc $(GLOBUS_THREAD_PKGCONF)
libexec_SCRIPTS = build-aux/config.guess

EXTRA_DIST = \
	dirt.sh \
	globus_common.txt \
	$(doc_DATA)

distuninstallcheck:
	@:
