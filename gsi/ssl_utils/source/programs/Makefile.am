include $(top_srcdir)/globus_automake_pre

User_Scripts = \
	grid-cert-info \
	grid-cert-renew \
	grid-change-pass-phrase \
	grid-cert-request

Admin_Scripts = \
	grid-mapfile-add-entry \
	grid-mapfile-delete-entry \
	grid-mapfile-check-consistency

Dist_Scripts = \
	grid-cert-info.in \
	grid-cert-renew.in \
	grid-change-pass-phrase.in \
	grid-cert-request.in \
	grid-mapfile-add-entry.in \
	grid-mapfile-delete-entry.in \
	grid-mapfile-check-consistency.in

bin_SCRIPTS = $(User_Scripts)

sbin_SCRIPTS = $(Admin_Scripts)

EXTRA_DIST = $(Dist_Scripts)

bin_PROGRAMS = grid-proxy-init grid-proxy-destroy grid-proxy-info

INCLUDES = -I$(top_srcdir)/library $(GPT_INCLUDES) 


grid_proxy_init_SOURCES = grid_proxy_init.c
grid_proxy_destroy_SOURCES = grid_proxy_destroy.c
grid_proxy_info_SOURCES = grid_proxy_info.c

grid_proxy_init_LDADD = ../library/libglobus_ssl_utils_$(GLOBUS_FLAVOR_NAME).la @GPT_PGM_LINKS@
grid_proxy_destroy_LDADD = ../library/libglobus_ssl_utils_$(GLOBUS_FLAVOR_NAME).la @GPT_PGM_LINKS@
grid_proxy_info_LDADD =  ../library/libglobus_ssl_utils_$(GLOBUS_FLAVOR_NAME).la @GPT_PGM_LINKS@

grid_proxy_init_LDFLAGS = @GPT_LDFLAGS@
grid_proxy_destroy_LDFLAGS = @GPT_LDFLAGS@
grid_proxy_info_LDFLAGS = @GPT_LDFLAGS@


include $(top_srcdir)/globus_automake_post

