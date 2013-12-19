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
SUFFIXES = .xml .1

.xml.1:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) $<
CLEANFILES = $(man_MANS)
endif
