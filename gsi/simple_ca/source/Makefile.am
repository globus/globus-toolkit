include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

bin_SCRIPTS = grid-ca-sign grid-ca-create grid-ca-package
pkgdata_DATA = \
        ca-signing-policy.tmpl \
        grid-ca-ssl.conf.tmpl \
        grid-security.conf.tmpl

doc_DATA = GLOBUS_LICENSE
man1_MANS = grid-ca-create.1 grid-ca-package.1 grid-ca-sign.1

MANUALS_SOURCE = \
    grid-ca-create-manual.xml \
    grid-ca-package-manual.xml \
    grid-ca-sign-manual.xml \
    manual.xml \
    replace-version.xsl


SUBDIRS = pkgdata

EXTRA_DIST = $(pkgdata_DATA) $(doc_DATA) \
             grid-ca-sign.in grid-ca-create.in grid-ca-package.in \
             $(man1_MANS) $(MANUALS_SOURCE)

if GENERATE_MANPAGES
export XML_CATALOG_FILES :=  $(XML_CATALOG_PATH)

$(man1_MANS): $(MANUALS_SOURCE)
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd manual.xml > /dev/null
	$(XSLTPROC) --stringparam version "`$$GLOBUS_LOCATION/bin/globus-version 2> /dev/null || echo`" --xinclude replace-version.xsl manual.xml
endif

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
