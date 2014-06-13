data_DATA = \
	globus-user-env.sh \
	globus-user-env.csh
libexecdatadir = $(libexecdir)
libexecdata_DATA = \
	globus-args-parser-header \
	globus-sh-tools.sh \
	globus-sh-tools-vars.sh \
	globus-script-initializer \
	globus-script-initializer.$(host_cpu)-$(host_vendor)-$(host_os)
libexec_SCRIPTS = \
	globus-vararg-enums-doxygen-filter.pl

bin_SCRIPTS = \
	globus-hostname \
	globus-domainname \
	globus-makefile-header

globuscore_perlmoduledir = $(perlmoduledir)/Globus/Core
globuscore_perlmodule_DATA = Config.pm Paths.pm

all-local:
	$(MKDIR_P) Globus/Core
	$(INSTALL) $(srcdir)/Config.pm Paths.pm Globus/Core

clean-local:
	rm -rf Globus

DISTCLEANFILES = globus-script-initializer.$(host_cpu)-$(host_vendor)-$(host_os)

EXTRA_DIST = \
	globus-args-parser-header \
	globus-vararg-enums-doxygen-filter.pl \
	Config.pm
