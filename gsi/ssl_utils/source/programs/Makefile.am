include $(top_srcdir)/globus_automake_pre

Scripts= \
	grid-cert-info \
	grid-cert-renew \
	grid-change-pass-phrase \
	grid-cert-request

bin_SCRIPTS = $(Scripts)
EXTRA_DIST = $(Scripts)

bin_PROGRAMS = grid-proxy-init grid-proxy-destroy grid-proxy-info

INCLUDES = $(GPT_INCLUDES) -I $(top_srcdir)/library


grid_proxy_init_SOURCES = grid_proxy_init.c
grid_proxy_destroy_SOURCES = grid_proxy_destroy.c
grid_proxy_info_SOURCES = grid_proxy_info.c

grid_proxy_init_LDADD = ../library/libglobus_ssl_utils_$(GLOBUS_FLAVOR_NAME).la @GPT_PGM_LINKS@
grid_proxy_destroy_LDADD = ../library/libglobus_ssl_utils_$(GLOBUS_FLAVOR_NAME).la @GPT_PGM_LINKS@
grid_proxy_info_LDADD =  ../library/libglobus_ssl_utils_$(GLOBUS_FLAVOR_NAME).la @GPT_PGM_LINKS@

include $(top_srcdir)/globus_automake_post

