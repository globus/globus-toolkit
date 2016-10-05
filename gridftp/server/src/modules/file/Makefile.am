noinst_LTLIBRARIES = libglobus_gridftp_server_file.la

AM_CPPFLAGS = -I$(top_srcdir) -DGLOBUS_BUILTIN=1 $(PACKAGE_DEP_CFLAGS) $(OPENSSL_CFLAGS) $(ZLIB_CFLAGS)

libglobus_gridftp_server_file_la_SOURCES = globus_gridftp_server_file.c
libglobus_gridftp_server_file_la_LIBADD = $(PACKAGE_DEP_LIBS) $(OPENSSL_LIBS) $(ZLIB_LIBS)
