include $(top_srcdir)/globus_automake_pre

man1datadir=$(mandir)/man1
man8datadir=$(mandir)/man8

man1data_DATA = grid-cert-info.1 \
        grid-cert-request.1 \
        grid-change-pass-phrase.1
man8data_DATA = grid-default-ca.8
MANUALS_SOURCE = manual.xml \
        grid-cert-info-manual.xml \
        grid-cert-request-manual.xml \
        grid-change-pass-phrase-manual.xml \
        grid-default-ca-manual.xml
        
User_Scripts = \
	grid-cert-info \
	grid-change-pass-phrase \
	grid-cert-request \
	grid-default-ca

Dist_Scripts = \
        grid-cert-info.in \
        grid-change-pass-phrase.in \
        grid-cert-request.in \
	grid-default-ca.in

bin_SCRIPTS = $(User_Scripts)

EXTRA_DIST = $(Dist_Scripts) $(MANUALS_SOURCE) $(man1data_DATA) $(man8data_DATA)

if GENERATE_MANPAGES
export XML_CATALOG_FILES :=  $(XML_CATALOG_PATH)

$(man1data_DATA) $(man8data_DATA): $(MANUALS_SOURCE)
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd manual.xml > /dev/null
	$(XSLTPROC) --stringparam version "`$$GLOBUS_LOCATION/bin/globus-version 2> /dev/null || echo`" --xinclude replace-version.xsl manual.xml
endif

grid-cert-info: grid-cert-info.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

grid-change-pass-phrase: grid-change-pass-phrase.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

grid-cert-request: grid-cert-request.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

grid-default-ca: grid-default-ca.in
	$(REWRITE_SCRIPT_PREFIXES) < $< > $@

CLEANFILES = $(User_Scripts)

BUILT_SOURCES = $(User_Scripts)

include $(top_srcdir)/globus_automake_post


