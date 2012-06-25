include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= schemas pkgdata

# Where targets are installed
sbin_SCRIPTS = globus-gram-audit

## man8 = [ DOC ]
man8_MANS = globus-gram-audit.8
MANUAL_SOURCE = manual.xml globus-gram-audit-manual.xml 

## globusconf = [ DATA ]
globusconfdir = $(sysconfdir)/globus
globusconf_DATA = gram-audit.conf

## cron = [ PROGRAMS ]
crondir = $(sysconfdir)/cron.hourly
cron_SCRIPTS = globus-gram-audit.cron

doc_DATA = GLOBUS_LICENSE

# Files which we want to put in the source package
EXTRA_DIST = globus-gram-audit.in $(man8_MANS) $(MANUAL_SOURCE) \
	gram-audit.conf.in $(doc_DATA)

if GENERATE_MANPAGES
export XML_CATALOG_FILES :=  $(XML_CATALOG_PATH)

$(man8_MANS): $(MANUAL_SOURCE)
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd manual.xml > /dev/null
	$(XSLTPROC) --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl manual.xml
endif

install-data-hook:
	mkdir -p -m 01733 $(DESTDIR)$(localstatedir)/lib/globus/gram-audit

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
