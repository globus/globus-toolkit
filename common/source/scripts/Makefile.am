include $(top_srcdir)/globus_automake_pre

libexec_SCRIPTS = \
	globus-args-parser-header \
	globus-sh-tools.sh

sbin_SCRIPTS = \
	globus-build-doxygen-dependencies 

bin_SCRIPTS = \
	globus-hostname \
	globus-domainname \
	globus-makefile-header

globus-domainname: globus-hostname
	cp $(srcdir)/globus-hostname $(builddir)/scripts/globus-domainname

EXTRA_DIST = \
	globus-args-parser-header \
	globus-sh-tools.sh \
	globus-hostname \
	globus-build-doxygen-dependencies \
	globus-makefile-header

include $(top_srcdir)/globus_automake_post