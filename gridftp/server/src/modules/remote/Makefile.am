noinst_LTLIBRARIES = libglobus_gridftp_server_remote.la

AM_CPPFLAGS = -I$(top_srcdir) -DGLOBUS_BUILTIN=1 $(PACKAGE_DEP_CFLAGS) $(OPENSSL_CFLAGS)
libglobus_gridftp_server_remote_la_SOURCES = globus_gridftp_server_remote.c
libglobus_gridftp_server_remote_la_LIBADD = $(PACKAGE_DEP_LIBS) $(OPENSSL_LIBS)
