include $(top_srcdir)/globus_automake_pre

libexec_SCRIPTS = \
	globus-args-parser-header \
	globus-sh-tools.sh

sbin_SCRIPTS = \
	globus-build-doxygen-dependencies 

bin_SCRIPTS = \
	globus-hostname \
	globus-domainname \
	globus-makefile-header \
	globus-makefile-header.gpt1

globus-domainname: globus-hostname
	cp $(srcdir)/globus-hostname $(builddir)/globus-domainname

EXTRA_DIST = \
	globus-args-parser-header \
	globus-sh-tools.sh \
	globus-hostname \
	globus-build-doxygen-dependencies \
	globus-makefile-header \
	globus-makefile-header.gpt1

include $(top_srcdir)/globus_automake_post
