include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS=\
	pkgdata

bin_PROGRAMS= \
    backend-idle \
    gridftp-register \
    monitor \
    zero-idle \
    globus-get-rp \
    globus-get-ip

backend_idle_Sources= backend_idle.c
monitor_Sources= monitor.c
zero_idle_Sources= zero_idle.c
gridftp_register_Sources= gridftp_register.c
globus_get_ip_Sources= globus_get_ip.c
globus_get_rp_Sources= globus_get_rp.c globus_get_rp_opts.c

client_time_plugin_Sources=globus_ftp_client_time_plugin.c
lib_LTLIBRARIES = libclient_time_plugin_$(GLOBUS_FLAVOR_NAME).la
libclient_time_plugin___GLOBUS_FLAVOR_NAME__la_CFLAGS = $(GPT_CFLAGS)
libclient_time_plugin___GLOBUS_FLAVOR_NAME__la_LIBADD = \
    @GPT_LIB_LINKS@
libclient_time_plugin___GLOBUS_FLAVOR_NAME__la_SOURCES = $(client_time_plugin_Sources)
libclient_time_plugin___GLOBUS_FLAVOR_NAME__la_LDFLAGS = \
 -L @GPT_LDFLAGS@ -module -rpath $(GLOBUS_LOCATION)/lib


EXTRA_DIST =
INCLUDES = $(GPT_INCLUDES)
LDADD = $(GPT_PGM_LINKS)

backend_idle_CFLAGS  = $(GPT_CFLAGS)
backend_idle_SOURCES = $(backend_idle_Sources)
backend_idle_LDFLAGS = $(GPT_LDFLAGS)

gridftp_register_CFLAGS  = $(GPT_CFLAGS)
gridftp_register_SOURCES = $(gridftp_register_Sources)
gridftp_register_LDFLAGS = $(GPT_LDFLAGS)
globus_get_ip_CFLAGS  = $(GPT_CFLAGS)
globus_get_ip_SOURCES = $(globus_get_ip_Sources)
globus_get_ip_LDFLAGS = $(GPT_LDFLAGS)
globus_get_rp_CFLAGS  = $(GPT_CFLAGS)
globus_get_rp_SOURCES = $(globus_get_rp_Sources)
globus_get_rp_LDFLAGS = $(GPT_LDFLAGS)

monitor_CFLAGS  = $(GPT_CFLAGS)
monitor_SOURCES = $(monitor_Sources)
monitor_LDFLAGS = $(GPT_LDFLAGS)

zero_idle_CFLAGS  = $(GPT_CFLAGS)
zero_idle_SOURCES = $(zero_idle_Sources)
zero_idle_LDFLAGS = $(GPT_LDFLAGS)


include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
