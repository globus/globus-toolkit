pkgconfigdir = $(libdir)/pkgconfig

SUBDIRS = library
man_MANS = globus-update-certificate-dir.8
doc_DATA = GLOBUS_LICENSE
sbin_SCRIPTS = globus-update-certificate-dir
pkgconfig_DATA = globus-openssl-module.pc

MANUAL_SOURCE = globus-update-certificate-dir.xml

if BUILD_MANPAGES
SUFFIXES = .xml .8
.xml.8:
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd $< > /dev/null
	$(XSLTPROC) --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
endif

EXTRA_DIST = \
	dirt.sh \
	version.h.in \
	globus-update-certificate-dir.in \
	$(man_MANS) \
	$(MANUAL_SOURCE) \
	$(doc_DATA)

distuninstallcheck:
	@:
