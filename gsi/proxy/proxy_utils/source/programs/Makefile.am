bin_PROGRAMS = grid-proxy-init grid-proxy-info grid-proxy-destroy \
               grid-cert-diagnostics

man_MANS = grid-proxy-init.1 grid-proxy-info.1 grid-proxy-destroy.1 \
        grid-cert-diagnostics.1

MANUALS_SOURCE = \
        grid-proxy-init.txt \
        grid-proxy-info.txt \
        grid-proxy-destroy.txt \
        grid-cert-diagnostics.txt

AM_CPPFLAGS =  -I$(top_srcdir) $(PACKAGE_DEP_CFLAGS) $(OPENSSL_CFLAGS)
AM_LDFLAGS = $(PACKAGE_DEP_LIBS) $(OPENSSL_LIBS)

grid_proxy_init_SOURCES = grid_proxy_init.c globus_stdio_ui.c globus_stdio_ui.h
grid_proxy_info_SOURCES = grid_proxy_info.c
grid_proxy_destroy_SOURCES = grid_proxy_destroy.c

EXTRA_DIST = $(MANUALS_SOURCE) $(man_MANS)

if BUILD_MANPAGES
SUFFIXES = .txt .1

.txt.1:
	$(A2X) -f manpage -d manpage $<
MAINTAINERCLEANFILES = $(man_MANS)
endif
