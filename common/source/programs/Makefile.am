include $(top_srcdir)/globus_automake_pre

sbin_SCRIPTS = globus-update-doxygen-index
libexec_PROGRAMS = globus-libc-hostname

INCLUDES = -I $(top_srcdir)/library $(GPT_INCLUDES) 

globus_libc_hostname_SOURCES = globus_libc_hostname.c

globus_libc_hostname_LDADD = ../library/libglobus_common_$(GLOBUS_FLAVOR_NAME).la @GPT_PGM_LINKS@

include $(top_srcdir)/globus_automake_post

