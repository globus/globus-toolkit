include $(top_srcdir)/globus_automake_pre

libexec_SCRIPTS = \
	globus-args-parser-header \
	globus-sh-tools.sh \
        globus-script-initializer

bin_SCRIPTS = \
	globus-hostname \
	globus-domainname \
	globus-makefile-header

perllibdir = ${libdir}/perl/Globus/Core
perllib_SCRIPTS = Paths.pm

globus-hostname: globus-hostname.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-domainname: globus-hostname.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-sh-tools.sh: globus-sh-tools.sh.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-makefile-header: globus-makefile-header.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-script-initializer: globus-script-initializer.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
Paths.pm: Paths.pm.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

BUILT_SOURCES = globus-hostname globus-domainname \
                globus-sh-tools.sh globus-makefile-header \
                globus-script-initializer Paths.pm

clean-local:
	-rm -f $(BUILT_SOURCES)

EXTRA_DIST = \
	globus-args-parser-header \
	globus-sh-tools.sh.in \
	globus-hostname.in \
	globus-makefile-header.in \
        Paths.pm.in globus-script-initializer.in

include $(top_srcdir)/globus_automake_post
