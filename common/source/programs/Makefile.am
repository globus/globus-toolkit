include $(top_srcdir)/globus_automake_pre

if ENABLE_PROGRAMS
bin_SCRIPTS = globus-sh-exec globus-version

sbin_PROGRAMS = globus-libc-hostname globus-redia

INCLUDES = -I$(top_srcdir)/library $(GPT_INCLUDES) 

globus_redia_SOURCES = globus_redia.c
globus_redia_LDFLAGS = @GPT_LDFLAGS@
globus_redia_LDADD = ../library/libglobus_common.la @GPT_PGM_LINKS@

globus_libc_hostname_SOURCES = globus_libc_hostname.c
globus_libc_hostname_LDFLAGS = @GPT_LDFLAGS@

globus_libc_hostname_LDADD = ../library/libglobus_common.la @GPT_PGM_LINKS@
endif

EXTRA_DIST = globus-sh-exec.in globus-version.in

include $(top_srcdir)/globus_automake_post

