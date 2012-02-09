include $(top_srcdir)/globus_automake_pre

man_MANS = \
    globus-domainname.1 \
    globus-hostname.1 \
    globus-sh-exec.1 \
    globus-version.1

man_xml_source = \
    globus-domainname.xml \
    globus-hostname.xml \
    globus-sh-exec.xml \
    globus-version.xml

EXTRA_DIST = $(man_MANS) $(man_xml_source)

if BUILD_MANPAGES
export XML_CATALOG_FILES :=  $(XML_CATALOG_PATH)

MAN_XSL=http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl
DOCBOOK_DTD=http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd


%.1: %.xml
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) $<
CLEANFILES = $(man_MANS)
endif

include $(top_srcdir)/globus_automake_post
