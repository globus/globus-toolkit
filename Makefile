
GSI_DEVELOPMENT_PATH	=	/usr/local/gsi/development/i686-pc-linux-gnu_nothreads_standard_debug/

include $(GSI_DEVELOPMENT_PATH)/etc/makefile_header

LINK		=	$(CC)

####

TARGETS	=	gsi-socket-test

default:	$(TARGETS)

gsi-socket-test: gsi_socket_test.o gsi_socket.o
	$(LINK) $(LDFLAGS) $(GLOBUS_GSSAPI_LDFLAGS) \
		-o $@ $^ $(GLOBUS_GSSAPI_LIBS)

myproxy_init: myproxy_init.o gsi_socket.o gnu_getopt.o gnu_getopt_long.o
	$(CC) $(LDFLAGS) $(GLOBUS_GSSAPI_LDFLAGS) \
		-o $@ $^ $(GLOBUS_GSSAPI_LIBS)

gnu_getopt.o: gnu_getopt.c
	$(CC) -c $<

gnu_getopt_long.o: gnu_getopt_long.c
	$(CC) -c $<

clean:
	rm -f *.o
	rm -f $(TARGETS)
