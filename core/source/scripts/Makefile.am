include $(top_srcdir)/aclocal/automake_targets

corescriptsdir=${exec_prefix}/share/globus
corescripts_SCRIPTS = \
	globus-build-env-$(GLOBUS_FLAVOR_NAME).sh \
	globus-build-env-noflavor.sh \
	globus-bootstrap.sh

bin_SCRIPTS = globus-spec-creator
man1_MANS = globus-spec-creator.1

globus-spec-creator.1: globus-spec-creator
	pod2man globus-spec-creator > globus-spec-creator.1

EXTRA_DIST = \
	globus-build-env.sh.in \
	globus-build-env-noflavor.sh.in \
	globus-bootstrap.sh.in \
	globus-spec-creator
