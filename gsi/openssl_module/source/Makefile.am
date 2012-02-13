include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	library \
	pkgdata \
	doxygen

## man8dir = [ DOC ]

man8_MANS = globus-update-certificate-dir.8

doc_DATA = GLOBUS_LICENSE

sbin_SCRIPTS = globus-update-certificate-dir

MANUAL_SOURCE = globus-update-certificate-dir-manual.xml \
                manual.xml

EXTRA_DIST = \
	version.h.in \
	globus-update-certificate-dir.in \
	$(man8_MANS) \
	$(MANUAL_SOURCE) \
	$(doc_DATA)

if GENERATE_MANPAGES
export XML_CATALOG_FILES :=  $(XML_CATALOG_PATH)

$(man8_MANS): $(MANUAL_SOURCE)
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd manual.xml > /dev/null
	$(XSLTPROC) --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl manual.xml
endif

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
