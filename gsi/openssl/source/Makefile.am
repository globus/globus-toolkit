include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

lib_LTLIBRARIES = libglobus_openssl_version_$(GLOBUS_FLAVOR_NAME).la
libexec_PROGRAMS = globus-openssl-version
nodist_flavorinclude_HEADERS = globus_openssl_version.h
nodist_flavorincludedir = $(flavorincludedir)

SUBDIRS = pkgdata

EXTRA_DIST = dirt.sh

libglobus_openssl_version___GLOBUS_FLAVOR_NAME__la_SOURCES = \
    globus_openssl_version.c

globus_openssl_version_SOURCES = main.c

globus_openssl_version.h: globus-openssl-version
	./globus-openssl-version -H > globus_openssl_version.h

CLEANFILES = globus_openssl_version.h

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

