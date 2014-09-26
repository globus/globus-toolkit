ACLOCAL_AMFLAGS=-I m4
bin_SCRIPTS = \
	globus-gass-cache \
	globus-gass-cache-destroy
libexec_SCRIPTS = \
	globus-gass-cache-util.pl
bin_PROGRAMS = \
	globus-gass-cache-util
doc_DATA = GLOBUS_LICENSE

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)

globus_gass_cache_util_LDADD = $(PACKAGE_DEP_LIBS)
globus_gass_cache_util_SOURCES = globus_gass_cache.c

EXTRA_DIST = \
	dirt.sh \
	$(doc_DATA)

distuninstallcheck:
	@:
