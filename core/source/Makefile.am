include $(top_srcdir)/aclocal/automake_targets

doc_DATA = GLOBUS_LICENSE

flavorinclude_HEADERS = \
	globus_config.h

SUBDIRS = aclocal config scripts pkgdata doxygen


EXTRA_DIST = bootstrap GLOBUS_LICENSE dirt.sh globus-core.spec gptdata.sh

dist-hook:
	$(GPT_LOCATION)/sbin/gpt_create_automake_rules -srcdir=$(top_distdir)

DISTCLEANFILES = globus-script-initializer globus-perl-initializer
