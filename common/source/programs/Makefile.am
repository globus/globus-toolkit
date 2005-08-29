include $(top_srcdir)/globus_automake_pre

if ENABLE_PROGRAMS
bin_SCRIPTS = globus-sh-exec globus-version
sbin_SCRIPTS = globus-update-doxygen-index \
        globus-vararg-enums-doxygen-filter.pl

libexec_PROGRAMS = globus-libc-hostname globus-is-local-user

EXTRA_DIST = $(sbin_SCRIPTS) globus-sh-exec.in globus-version.in

INCLUDES = -I$(top_srcdir)/library $(GPT_INCLUDES) 

globus_libc_hostname_SOURCES = globus_libc_hostname.c
globus_libc_hostname_LDFLAGS = @GPT_LDFLAGS@

globus_libc_hostname_LDADD = ../library/libglobus_common_$(GLOBUS_FLAVOR_NAME).la @GPT_PGM_LINKS@


globus_is_local_user_SOURCES = globus_is_local_user.c
globus_is_local_user_LDFLAGS = @GPT_LDFLAGS@

globus_is_local_user_LDADD = ../library/libglobus_common_$(GLOBUS_FLAVOR_NAME).la @GPT_PGM_LINKS@
endif

include $(top_srcdir)/globus_automake_post

