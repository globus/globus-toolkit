include $(top_srcdir)/globus_automake_pre

Admin_Scripts = \
	grid-mapfile-add-entry \
	grid-mapfile-delete-entry \
	grid-mapfile-check-consistency

Dist_Scripts = \
        grid-mapfile-add-entry.in \
        grid-mapfile-delete-entry.in \
        grid-mapfile-check-consistency.in

sbin_SCRIPTS = $(Admin_Scripts)
man8datadir=$(mandir)/man8
man8data_DATA=  grid-mapfile-add-entry.8 \
                grid-mapfile-delete-entry.8 \
                grid-mapfile-check-consistency.8

MANUALS_SOURCE = manual.xml \ 
        grid-mapfile-add-entry-manual.xml \
        grid-mapfile-delete-entry-manual.xml \
        grid-mapfile-check-consistency-manual.xml \
        replace-version.xsl 

EXTRA_DIST = $(Dist_Scripts) $(MANUALS_SOURCE) $(man8data_DATA)

INCLUDES =  -I$(top_srdir) $(GPT_INCLUDES) 

if GENERATE_MANPAGES
export XML_CATALOG_FILES :=  $(XML_CATALOG_PATH)

$(man8data_DATA): $(MANUALS_SOURCE)
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd manual.xml > /dev/null
	$(XSLTPROC) --stringparam version "`$$GLOBUS_LOCATION/bin/globus-version 2> /dev/null || echo`" --xinclude replace-version.xsl manual.xml
endif


include $(top_srcdir)/globus_automake_post
