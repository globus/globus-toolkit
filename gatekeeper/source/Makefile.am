include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= pkgdata config init

INCLUDES = $(GPT_INCLUDES)
LDADD = $(GPT_PGM_LINKS) @LIBOBJS@

sbin_PROGRAMS= \
	globus-gatekeeper \
	globus-k5

globus_gatekeeper_SOURCES = \
	globus_gatekeeper.c \
	globus_gatekeeper_utils.h \
	globus_gatekeeper_utils.c
globus_gatekeeper_LDFLAGS = $(GPT_LDFLAGS)

globus_k5_SOURCES = globus_k5.c globus_gatekeeper_utils.c
globus_k5_LDFLAGS = $(GPT_LDFLAGS)

globus_gatekeeper_CFLAGS = -DGLOBUS_LOCATION=\"$(prefix)\" -DGLOBUS_LOG_DIR=\"$(localstatedir)\"

## man8dir = [ DOC ]
man8_MANS = globus-gatekeeper.8 globus-k5.8
MANUAL_Sources = manual.xml globus-gatekeeper-manual.xml globus-k5-manual.xml

doc_DATA = GLOBUS_LICENSE

EXTRA_DIST=$(doc_DATA) $(man8_MANS) $(MANUAL_Sources)

if GENERATE_MANPAGES
export XML_CATALOG_FILES :=  $(XML_CATALOG_PATH)

$(man8_MANS): $(MANUAL_Sources)
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd manual.xml > /dev/null
	$(XSLTPROC) --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl manual.xml
endif

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
