include $(top_srcdir)/globus_automake_pre

libexec_SCRIPTS = \
	globus-args-parser-header \
	globus-sh-tools.sh \
	globus-sh-tools-vars.sh \
        globus-script-initializer

bin_SCRIPTS = \
	globus-hostname \
	globus-domainname \
	globus-makefile-header

perllibdir = ${libdir}/perl/Globus/Core
perllib_SCRIPTS = Paths.pm

EXTRA_DIST = \
	globus-args-parser-header \
	globus-sh-tools.sh.in \
	globus-sh-tools-vars.sh.in \
	globus-hostname.in \
	globus-makefile-header.in \
        Paths.pm.in globus-script-initializer.in

include $(top_srcdir)/globus_automake_post
