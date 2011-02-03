include $(top_srcdir)/globus_automake_pre

bin_PROGRAMS = grid-proxy-init grid-proxy-info grid-proxy-destroy \
               grid-cert-diagnostics

## man1dir = [ DOC ]
man1_MANS = grid-proxy-init.1 grid-proxy-info.1 grid-proxy-destroy.1 \
        grid-cert-diagnostics.1
MANUALS_SOURCE = manual.xml \
        grid_proxy_init-manual.xml \
        grid_proxy_info-manual.xml \
        grid_proxy_destroy-manual.xml \
        grid_cert_diagnostics-manual.xml \
        replace-version.xsl

INCLUDES =  -I$(top_srcdir) $(GPT_INCLUDES) 

grid_cert_diagnostics_SOURCES = grid_cert_diagnostics.c
grid_cert_diagnostics_LDFLAGS = $(GPT_LDFLAGS)
grid_proxy_init_SOURCES = grid_proxy_init.c globus_stdio_ui.c globus_stdio_ui.h
grid_proxy_init_LDFLAGS = $(GPT_LDFLAGS)
grid_proxy_destroy_SOURCES = grid_proxy_destroy.c
grid_proxy_destroy_LDFLAGS = $(GPT_LDFLAGS)
grid_proxy_info_SOURCES = grid_proxy_info.c
grid_proxy_info_LDFLAGS = $(GPT_LDFLAGS)

LDADD = $(GPT_PGM_LINKS)

EXTRA_DIST = $(MANUALS_SOURCE) $(man1_MANS)

if GENERATE_MANPAGES
export XML_CATALOG_FILES :=  $(XML_CATALOG_PATH)

$(man1_MANS): $(MANUALS_SOURCE)
	$(XMLLINT) --xinclude --dtdvalid http://www.oasis-open.org/docbook/xml/4.4/docbookx.dtd manual.xml > /dev/null
	$(XSLTPROC) --stringparam version "`$$GLOBUS_LOCATION/bin/globus-version 2> /dev/null || echo`" --xinclude replace-version.xsl manual.xml
endif


include $(top_srcdir)/globus_automake_post
