include $(top_srcdir)/globus_automake_pre

bin_PROGRAMS = grid-proxy-init grid-proxy-info grid-proxy-destroy \
               grid-cert-diagnostics

INCLUDES =  -I$(top_srcdir) $(GPT_INCLUDES) 

grid_cert_diagnostics_SOURCES = grid_cert_diagnostics.c
grid_proxy_init_SOURCES = grid_proxy_init.c globus_stdio_ui.c globus_stdio_ui.h
grid_proxy_destroy_SOURCES = grid_proxy_destroy.c
grid_proxy_info_SOURCES = grid_proxy_info.c

LDADD = $(GPT_PGM_LINKS)
LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post
