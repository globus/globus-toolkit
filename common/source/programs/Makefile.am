bin_SCRIPTS = globus-sh-exec globus-version
sbin_PROGRAMS = globus-libc-hostname globus-redia

AM_CPPFLAGS = -I$(top_srcdir)/library $(PACKAGE_DEP_CFLAGS) 
AM_LDFLAGS = $(PACKAGE_DEP_LIBS)

globus_redia_SOURCES = globus_redia.c
globus_redia_LDADD = ../library/libglobus_common.la $(AM_LIBADD)

globus_libc_hostname_SOURCES = globus_libc_hostname.c
globus_libc_hostname_LDADD = ../library/libglobus_common.la $(AM_LIBADD)
