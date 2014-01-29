data_DATA = \
        globus-user-env.sh \
        globus-user-env.csh
libexec_SCRIPTS = \
	globus-args-parser-header \
	globus-sh-tools.sh \
	globus-sh-tools-vars.sh \
        globus-script-initializer \
        globus-script-initializer.$(host_cpu)-$(host_vendor)-$(host_os) \
        globus-vararg-enums-doxygen-filter.pl

bin_SCRIPTS = \
	globus-hostname \
	globus-domainname \
	globus-makefile-header

globuscore_perlmoduledir = $(perlmoduledir)/Globus/Core
globuscore_perlmodule_DATA = Config.pm Paths.pm

EXTRA_DIST = \
	globus-args-parser-header \
	globus-sh-tools.sh.in \
	globus-sh-tools-vars.sh.in \
	globus-hostname.in \
	globus-makefile-header.in \
        globus-vararg-enums-doxygen-filter.pl \
        Config.pm Paths.pm.in globus-script-initializer.in
