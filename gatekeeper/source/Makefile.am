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

man8datadir=$(mandir)/man8
man8data_DATA = globus-gatekeeper.8 globus-k5.8
MANUAL_Sources = manual.xml globus-gatekeeper-manual.xml globus-k5-manual.xml

EXTRA_DIST=$(man8data_DATA) $(MANUAL_Sources)

if GENERATE_MANPAGES
export XML_CATALOG_FILES :=  $(XML_CATALOG_PATH)

$(man8data_DATA): $(MANUAL_Sources)
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd manual.xml > /dev/null
	$(XSLTPROC) --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl manual.xml
endif

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
