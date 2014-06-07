man_MANS = grid-cert-info.1 \
        grid-cert-request.1 \
        grid-change-pass-phrase.1 \
        grid-default-ca.8

bin_SCRIPTS = $(User_Scripts)
sbin_SCRIPTS = $(Admin_Scripts)

MANUALS_SOURCE = \
        grid-cert-info.xml \
        grid-cert-request.xml \
        grid-change-pass-phrase.xml \
        grid-default-ca.xml

User_Scripts = \
	grid-cert-info \
	grid-change-pass-phrase \
	grid-cert-request
Admin_Scripts = \
	grid-default-ca

Dist_Scripts = \
        grid-cert-info.in \
        grid-change-pass-phrase.in \
        grid-cert-request.in \
	grid-default-ca.in


EXTRA_DIST = $(Dist_Scripts) $(MANUALS_SOURCE) $(man_MANS) \
    replace-version.xsl

if BUILD_MANPAGES
SUFFIXES = .xml .1 .8

.xml.8:
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd $< > /dev/null
	PATH=$${PATH}:$(bindir) $(XSLTPROC) --stringparam version "$${GLOBUS_VERSION:-`globus-version 2> /dev/null || echo`}" --xinclude $(srcdir)/replace-version.xsl $<
.xml.1:
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd $< > /dev/null
	PATH=$${PATH}:$(bindir) $(XSLTPROC) --stringparam version "$${GLOBUS_VERSION:-`globus-version 2> /dev/null || echo`}" --xinclude $(srcdir)/replace-version.xsl $<
MAINTAINERCLEANFILES = $(man_MANS)
endif

CLEANFILES = $(User_Scripts)

BUILT_SOURCES = $(User_Scripts)
