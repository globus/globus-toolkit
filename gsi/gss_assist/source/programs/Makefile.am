sbin_SCRIPTS = \
	grid-mapfile-add-entry \
	grid-mapfile-delete-entry \
	grid-mapfile-check-consistency

man_MANS =  grid-mapfile-add-entry.8 \
            grid-mapfile-delete-entry.8 \
            grid-mapfile-check-consistency.8

EXTRA_DIST = $(man_MANS) \
        grid-mapfile-add-entry.in \
        grid-mapfile-delete-entry.in \
        grid-mapfile-check-consistency.in \
        grid-mapfile-add-entry.xml \
        grid-mapfile-delete-entry.xml \
        grid-mapfile-check-consistency.xml \
        replace-version.xsl 

if BUILD_MANPAGES
SUFFIXES = .xml .8

.xml.8:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) $<
CLEANFILES = $(man_MANS)
endif
