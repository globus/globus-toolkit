include $(top_srcdir)/globus_automake_pre


INCLUDES = $(GPT_INCLUDES)

man8_MANS = globus-fork-starter.8

MANUAL_SOURCE = manual.xml

sbin_PROGRAMS = globus-fork-starter

globus_fork_starter_SOURCES = fork_starter.c
globus_fork_starter_LDFLAGS = $(GPT_LDFLAGS)
globus_fork_starter_LDADD = $(GPT_PGM_LINKS)

EXTRA_DIST= $(man8_MANS) $(MANUAL_SOURCE)

if GENERATE_MANPAGES
export XML_CATALOG_FILES :=  $(XML_CATALOG_PATH)

$(man8data_DATA): $(MANUAL_SOURCE)
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd manual.xml > /dev/null
	$(XSLTPROC) --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl manual.xml
endif

include $(top_srcdir)/globus_automake_post
