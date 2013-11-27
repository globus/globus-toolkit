AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I config -I .

pkgconfdir = ${libdir}/pkgconfig

SUBDIRS= \
	library \
	programs \
	scripts \
        manpages

libexec_SCRIPTS= \
	config.guess

doc_DATA = GLOBUS_LICENSE

pkgconf_DATA = globus-common.pc

EXTRA_DIST = \
	dirt.sh \
	version.h.in \
	globus_common.txt \
	$(doc_DATA)
