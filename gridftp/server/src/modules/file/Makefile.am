include $(top_srcdir)/globus_automake_pre

Sources= \
    globus_gridftp_server_file.c

noinst_LTLIBRARIES = libglobus_gridftp_server_file.la

INCLUDES = -I$(top_srcdir) $(GPT_INCLUDES) 

libglobus_gridftp_server_file_la_SOURCES = $(Sources)
libglobus_gridftp_server_file_la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_gridftp_server_file_la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
