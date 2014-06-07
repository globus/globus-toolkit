SUBDIRS = . test
bin_SCRIPTS = grid-ca-sign grid-ca-create grid-ca-package
doc_DATA = GLOBUS_LICENSE
man_MANS = grid-ca-create.1 grid-ca-package.1 grid-ca-sign.1

MANUALS_SOURCE = \
    grid-ca-create.xml \
    grid-ca-package.xml \
    grid-ca-sign.xml

EXTRA_DIST = \
        dirt.sh \
        ca-signing-policy.tmpl \
        grid-ca-ssl.conf.tmpl \
        grid-security.conf.tmpl \
        $(doc_DATA) \
        grid-ca-sign.in \
        grid-ca-create.in \
        grid-ca-package.in \
        $(man_MANS) \
        $(MANUALS_SOURCE)

if BUILD_MANPAGES
SUFFIXES = .xml .1

.xml.1:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) $<
MAINTAINERCLEANFILES = $(man_MANS)
endif

distuninstallcheck:
	@:
