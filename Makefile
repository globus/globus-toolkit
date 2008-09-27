include makefile_header
# include additional makefile headers here

# add needed cflags here
DSI_CFLAGS=$(GLOBUS_CFLAGS)  -ggdb

# add needed includes here
DSI_INCLUDES=$(GLOBUS_INCLUDES) -I/home/brian/software/hadoop-0.18.1/src/c++/libhdfs -I/opt/osg/osg-100/jdk1.5/include -I/opt/osg/osg-100/jdk1.5/include/linux

# added needed ldflags here
DSI_LDFLAGS=$(GLOBUS_LDFLAGS) -fPIC -L/home/brian/software/hadoop-0.18.1/build/libhdfs

# add needed libraries here
DSI_LIBS=-lhdfs

FLAVOR=gcc64dbg

globus_gridftp_server_hdfs.o:
	$(GLOBUS_CC) $(DSI_CFLAGS) $(DSI_INCLUDES) \
		-shared -o libglobus_gridftp_server_hdfs_$(FLAVOR).so \
		globus_gridftp_server_hdfs.c \
		$(DSI_LDFLAGS) $(DSI_LIBS)

install:
	cp -f libglobus_gridftp_server_hdfs_$(FLAVOR).so $(GLOBUS_LOCATION)/lib

clean:
	rm -f *.so
