
lib_LTLIBRARIES = libglobus_gridftp_server_hdfs.la

AM_CPPFLAGS = -I$(JNIHDIR) -I$(JNIHDIR)/linux @INCLUDE@ $(GLOBUS_GRIDFTP_SERVER_CFLAGS)

libglobus_gridftp_server_hdfs_la_LDFLAGS = -lhdfs -lcrypto -lz $(GLOBUS_GRIDFTP_SERVER_LIBS) -R/usr/lib/jvm/default-java/jre/lib/amd64/server \
    -avoid-version -no-undefined
libglobus_gridftp_server_hdfs_la_SOURCES = \
    gridftp_hdfs.h \
    gridftp_hdfs_error.h \
    gridftp_hdfs.c \
    gridftp_hdfs_recv.c \
    gridftp_hdfs_send.c \
    gridftp_hdfs_stat.c \
    gridftp_hdfs_buffers.c \
    gridftp_hdfs_cksm.c

