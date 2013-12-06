AUTOMAKE_OPTIONS = foreign

pkgconfdir = $(libdir)/pkgconfig

SUBDIRS = library test

doc_DATA = GLOBUS_LICENSE
pkgconf_DATA = globus-gsi-proxy-ssl.pc

AM_DISTCHECK_CONFIGURE_FLAGS = --enable-silent-rules -q

EXTRA_DIST = $(doc_DATA)
