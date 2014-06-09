bin_PROGRAMS = grid-proxy-init grid-proxy-info grid-proxy-destroy \
               grid-cert-diagnostics

## mandir = [ DOC ]
man_MANS = grid-proxy-init.1 grid-proxy-info.1 grid-proxy-destroy.1 \
        grid-cert-diagnostics.1
MANUALS_SOURCE = manual.xml \
        grid_proxy_init.xml \
        grid_proxy_info.xml \
        grid_proxy_destroy.xml \
        grid_cert_diagnostics.xml \
        replace-version.xsl

AM_CPPFLAGS =  -I$(top_srcdir) $(PACKAGE_DEP_CFLAGS) 
AM_LDFLAGS = $(PACKAGE_DEP_LIBS)

grid_cert_diagnostics_SOURCES = grid_cert_diagnostics.c
grid_proxy_init_SOURCES = grid_proxy_init.c globus_stdio_ui.c globus_stdio_ui.h
grid_proxy_info_SOURCES = grid_proxy_info.c
grid_proxy_destroy_SOURCES = grid_proxy_destroy.c

EXTRA_DIST = $(MANUALS_SOURCE) $(man_MANS)

if BUILD_MANPAGES
SUFFIXES = .xml .1

.xml.1:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) $<
MAINTAINERCLEANFILES = $(man_MANS)
endif
