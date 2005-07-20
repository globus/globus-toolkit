## Process this file with automake to produce Makefile.in

include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen \
	web \
	man

LibSources= \
	auth_pam.c \
	auth_pam.h \
	getopt_long.c \
	gsi_socket.c \
	gsi_socket.h \
	gssapi.c \
	myproxy.c \
	myproxy.h \
	myproxy_authorization.c \
	myproxy_authorization.h \
	myproxy_common.h \
	myproxy_creds.c \
	myproxy_creds.h \
	myproxy_delegation.c \
	myproxy_delegation.h \
	myproxy_read_pass.c \
	myproxy_read_pass.h \
	myproxy_log.c \
	myproxy_log.h \
	myproxy_sasl_client.c \
	myproxy_sasl_client.h \
	myproxy_sasl_server.h \
	myproxy_sasl_server.c \
	myproxy_server.h \
	myproxy_server_config.c \
	plugin_common.c \
	plugin_common.h \
	port_getopt.h \
	ssl_utils.c \
	ssl_utils.h \
	string_funcs.c \
	string_funcs.h \
	verror.c \
	verror.h \
	vparse.c \
	vparse.h

Scripts= \
	myproxy-test \
	myproxy-replicate \
	myproxy-test-replicate \
	myproxy-admin-adduser

sbin_SCRIPTS = $(Scripts)

flavorinclude_HEADERS= \
	myproxy.h \
	myproxy_constants.h \
	myproxy_authorization.h \
	myproxy_protocol.h \
	myproxy_creds.h \
	myproxy_delegation.h \
	myproxy_log.h \
	myproxy_read_pass.h \
	myproxy_sasl_client.h \
	myproxy_sasl_server.h \
	myproxy_server.h \
	verror.h

lib_LTLIBRARIES = libmyproxy_$(GLOBUS_FLAVOR_NAME).la

libmyproxy___GLOBUS_FLAVOR_NAME__la_SOURCES = $(LibSources)

libmyproxy___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libmyproxy___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

bin_PROGRAMS= \
	myproxy-init \
	myproxy-info \
        myproxy-store \
	myproxy-destroy \
        myproxy-retrieve \
	myproxy-get-delegation \
	myproxy-logon \
	myproxy-change-pass-phrase

sbin_PROGRAMS= \
	myproxy-server \
	myproxy-admin-load-credential \
	myproxy-admin-query \
	myproxy-admin-change-pass

myproxy_init_SOURCES = 	myproxy_init.c

myproxy_init_LDFLAGS = $(GPT_LDFLAGS)

myproxy_init_LDADD = ./libmyproxy_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

myproxy_info_SOURCES = 	myproxy_info.c

myproxy_info_LDFLAGS = $(GPT_LDFLAGS)

myproxy_info_LDADD = ./libmyproxy_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

myproxy_store_SOURCES = myproxy_store.c

myproxy_store_LDFLAGS = $(GPT_LDFLAGS)

myproxy_store_LDADD = ./libmyproxy_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

myproxy_retrieve_SOURCES = myproxy_get_credential.c

myproxy_retrieve_LDFLAGS = $(GPT_LDFLAGS)

myproxy_retrieve_LDADD = ./libmyproxy_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

myproxy_destroy_SOURCES = myproxy_destroy.c

myproxy_destroy_LDFLAGS = $(GPT_LDFLAGS)

myproxy_destroy_LDADD = ./libmyproxy_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

myproxy_server_SOURCES = myproxy_server.c
myproxy_server_LDFLAGS = $(GPT_LDFLAGS)

myproxy_server_LDADD = ./libmyproxy_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

myproxy_get_delegation_SOURCES = myproxy_get_delegation.c

myproxy_get_delegation_LDFLAGS = $(GPT_LDFLAGS)

myproxy_get_delegation_LDADD = ./libmyproxy_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

myproxy_logon_SOURCES = myproxy_get_delegation.c

myproxy_logon_LDFLAGS = $(GPT_LDFLAGS)

myproxy_logon_LDADD = ./libmyproxy_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

myproxy_change_pass_phrase_SOURCES = myproxy_cp.c

myproxy_change_pass_phrase_LDFLAGS = $(GPT_LDFLAGS)

myproxy_change_pass_phrase_LDADD = ./libmyproxy_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

myproxy_admin_query_SOURCES = myproxy_arq.c

myproxy_admin_query_LDFLAGS = $(GPT_LDFLAGS)

myproxy_admin_query_LDADD = ./libmyproxy_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

myproxy_admin_load_credential_SOURCES = myproxy_alcf.c

myproxy_admin_load_credential_LDFLAGS = $(GPT_LDFLAGS)

myproxy_admin_load_credential_LDADD = ./libmyproxy_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

myproxy_admin_change_pass_SOURCES = myproxy_acp.c

myproxy_admin_change_pass_LDFLAGS = $(GPT_LDFLAGS)

myproxy_admin_change_pass_LDADD = ./libmyproxy_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

sysconf_DATA = myproxy-server.config

pkgdata_DATA = README INSTALL \
               LICENSE LICENSE.sasl LICENSE.netbsd \
               VERSION PROTOCOL \
               etc.services.modifications etc.inetd.conf.modifications \
               myproxy.cron \
               etc.init.d.myproxy etc.init.d.myproxy.nonroot \
               etc.xinetd.myproxy myproxy-passphrase-policy

EXTRA_DIST = $(Scripts) LICENSE LICENSE.sasl LICENSE.netbsd \
               VERSION PROTOCOL \
               myproxy-server.config \
               etc.services.modifications etc.inetd.conf.modifications \
               myproxy.cron \
               etc.init.d.myproxy etc.init.d.myproxy.nonroot \
               etc.xinetd.myproxy myproxy-passphrase-policy

dirt.sh:
	touch dirt.sh

config.h:
	touch config.h

KRB5CPPFLAGS = @KRB5CPPFLAGS@

gssapi.lo: gssapi.c plugin_common.h config.h
	$(LIBTOOL) --mode=compile $(CC) $(DEFS) $(KRB5CPPFLAGS) $(CFLAGS) -c gssapi.c

plugin_common.lo: plugin_common.c plugin_common.h config.h
	$(LIBTOOL) --mode=compile $(CC) $(DEFS) $(KRB5CPPFLAGS) $(CFLAGS) -c plugin_common.c

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
