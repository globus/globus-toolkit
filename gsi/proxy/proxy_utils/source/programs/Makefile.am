include $(top_srcdir)/globus_automake_pre

bin_PROGRAMS = grid-proxy-init-bin grid-proxy-info grid-proxy-destroy 

INCLUDES =  -I$(top_srcdir) $(GPT_INCLUDES) 

grid_proxy_init_bin_SOURCES = grid_proxy_init.c
grid_proxy_destroy_SOURCES = grid_proxy_destroy.c
grid_proxy_info_SOURCES = grid_proxy_info.c

grid_proxy_init_bin_LDADD =  @GPT_PGM_LINKS@
grid_proxy_destroy_LDADD = @GPT_PGM_LINKS@
grid_proxy_info_LDADD =  @GPT_PGM_LINKS@

grid_proxy_init_bin_LDFLAGS = @GPT_LDFLAGS@
grid_proxy_destroy_LDFLAGS = @GPT_LDFLAGS@
grid_proxy_info_LDFLAGS = @GPT_LDFLAGS@

include $(top_srcdir)/globus_automake_post
