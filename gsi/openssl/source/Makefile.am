include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

lib_LTLIBRARIES = libglobus_openssl_version.la
libexec_PROGRAMS = globus-openssl-version
bin_SCRIPTS = globus-update-certificate-dir
nodist_include_HEADERS = globus_openssl_version.h

## man8dir = [ DOC ]
man8_MANS = globus-update-certificate-dir.8

nodist_includedir = $(includedir)

SUBDIRS = pkgdata

doc_DATA = GLOBUS_LICENSE

MANUAL_SOURCE = globus-update-certificate-dir-manual.xml \
                manual.xml

EXTRA_DIST = dirt.sh globus-update-certificate-dir.in $(MANUAL_SOURCE) $(man8_MANS) $(doc_DATA)

libglobus_openssl_version_la_SOURCES = \
    globus_openssl_version.c

globus_openssl_version_SOURCES = main.c

globus_openssl_version.h: globus-openssl-version
	./globus-openssl-version -H > globus_openssl_version.h

CLEANFILES = globus_openssl_version.h 

if GENERATE_MANPAGES
export XML_CATALOG_FILES :=  $(XML_CATALOG_PATH)

$(man8_MANS): $(MANUAL_SOURCE)
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd manual.xml > /dev/null
	$(XSLTPROC) --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl manual.xml
endif


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

