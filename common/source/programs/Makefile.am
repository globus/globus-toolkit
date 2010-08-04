include $(top_srcdir)/globus_automake_pre

if ENABLE_PROGRAMS
bin_SCRIPTS = globus-sh-exec globus-version

libexec_PROGRAMS = globus-libc-hostname globus-redia

EXTRA_DIST = globus-sh-exec.in globus-version.in

INCLUDES = -I$(top_srcdir)/library $(GPT_INCLUDES) 

globus_redia_SOURCES = globus_redia.c
globus_redia_LDFLAGS = @GPT_LDFLAGS@
globus_redia_LDADD = ../library/libglobus_common_$(GLOBUS_FLAVOR_NAME).la @GPT_PGM_LINKS@

globus_libc_hostname_SOURCES = globus_libc_hostname.c
globus_libc_hostname_LDFLAGS = @GPT_LDFLAGS@

globus_libc_hostname_LDADD = ../library/libglobus_common_$(GLOBUS_FLAVOR_NAME).la @GPT_PGM_LINKS@

globus-sh-exec: $(srcdir)/globus-sh-exec.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@
globus-version: $(srcdir)/globus-version.in
	$(REWRITE_SCRIPT_PREFIXES) < $< | \
        sed -e 's|$(AT)GLOBUS_VERSION$(AT)|@GLOBUS_VERSION@|' \
            -e 's|$(AT)GLOBUS_VERSIONNAME$(AT)|@GLOBUS_VERSIONNAME@|' \
            > $@
endif

include $(top_srcdir)/globus_automake_post

