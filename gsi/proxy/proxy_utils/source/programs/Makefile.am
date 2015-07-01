bin_PROGRAMS = grid-proxy-init grid-proxy-info grid-proxy-destroy \
               grid-cert-diagnostics

## mandir = [ DOC ]
man_MANS = grid-proxy-init.1 grid-proxy-info.1 grid-proxy-destroy.1 \
        grid-cert-diagnostics.1
MANUALS_SOURCE = \
        grid-proxy-init.txt \
        grid-proxy-info.txt \
        grid-proxy-destroy.txt \
        grid-cert-diagnostics.txt \
        grid-proxy-init.xml \
        grid-proxy-info.xml \
        grid-proxy-destroy.xml \
        grid-cert-diagnostics.xml

AM_CPPFLAGS =  -I$(top_srcdir) $(PACKAGE_DEP_CFLAGS) 
AM_LDFLAGS = $(PACKAGE_DEP_LIBS)

grid_proxy_init_SOURCES = grid_proxy_init.c globus_stdio_ui.c globus_stdio_ui.h
grid_proxy_info_SOURCES = grid_proxy_info.c
grid_proxy_destroy_SOURCES = grid_proxy_destroy.c

EXTRA_DIST = $(MANUALS_SOURCE) $(man_MANS)

if BUILD_MANPAGES
SUFFIXES = .xml .1

if HAVE_A2X
SUFFIXES += .txt
.txt.xml:
	$(A2X) -f docbook -d manpage $<
endif

.xml.1:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) `test -f $< && echo $< || echo $(srcdir)/$<` > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) `test -f $< && echo $< || echo $(srcdir)/$<`
MAINTAINERCLEANFILES = $(man_MANS)
endif
