man_MANS = grid-cert-info.1 \
        grid-cert-request.1 \
        grid-change-pass-phrase.1 \
        grid-default-ca.8 \
        globus-update-certificate-dir.8

bin_SCRIPTS = $(User_Scripts)
sbin_SCRIPTS = $(Admin_Scripts)

MANUALS_SOURCE = \
        grid-cert-info.xml \
        grid-cert-request.xml \
        grid-change-pass-phrase.xml \
        grid-default-ca.xml \
        globus-update-certificate-dir.xml

User_Scripts = \
	grid-cert-info \
	grid-change-pass-phrase \
	grid-cert-request
Admin_Scripts = \
	grid-default-ca \
	globus-update-certificate-dir

EXTRA_DIST = $(MANUALS_SOURCE) $(man_MANS) \
    replace-version.xsl

if BUILD_MANPAGES
SUFFIXES = .xml .1 .8

.xml.8:
	$(XMLLINT) --nonet --xinclude --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet --stringparam version "$(GLOBUS_VERSION)" --xinclude $(srcdir)/replace-version.xsl $<
.xml.1:
	$(XMLLINT) --nonet --xinclude --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet --stringparam version "$(GLOBUS_VERSION)" --xinclude $(srcdir)/replace-version.xsl $<
MAINTAINERCLEANFILES = $(man_MANS)
endif
