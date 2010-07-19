include $(top_srcdir)/globus_automake_pre

Sources= \
    globus_gridftp_server_remote.c

noinst_LTLIBRARIES = libglobus_gridftp_server_remote_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) $(GPT_INCLUDES) 

libglobus_gridftp_server_remote___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_gridftp_server_remote___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_gridftp_server_remote___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
