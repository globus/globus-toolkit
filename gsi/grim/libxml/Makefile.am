include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top
include $(top_srcdir)/globus_libxml2_pre

SUBDIRS = include pkgdata

Sources=\
	SAX.c entities.c encoding.c error.c parserInternals.c  \
	parser.c tree.c hash.c list.c xmlIO.c xmlmemory.c uri.c  \
	valid.c xlink.c HTMLparser.c HTMLtree.c debugXML.c xpath.c  \
	xpointer.c xinclude.c nanohttp.c nanoftp.c DOCBparser.c \
	catalog.c globals.c threads.c c14n.c \
	xmlregexp.c xmlschemas.c xmlschemastypes.c xmlunicode.c \
        libxml.h trio.h triodef.h trionan.h triop.h triostr.h trionan.c

lib_LTLIBRARIES = libxml2_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = ${GPT_INCLUDES} -I$(top_srcdir)/include

libxml2___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libxml2___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@ @Z_LIBS@ -lm
libxml2___GLOBUS_FLAVOR_NAME__la_LDFLAGS = -version-info @LIBXML_VERSION_INFO@ @GPT_LDFLAGS@

EXTRA_DIST=

include $(top_srcdir)/globus_libxml2_post
include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
