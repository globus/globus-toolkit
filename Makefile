GSI_DEVELOPMENT_PATH	=	/usr/local/globus/development/i686-pc-linux-gnu_nothreads_standard_debug/

include $(GSI_DEVELOPMENT_PATH)/etc/makefile_header

LINK		=	$(CC)

GSI_SOCKET_CFLAGS	=	-DGSI_SOCKET_SSLEAY $(CFLAGS) -Wall
####

TARGETS	=	gsi-socket-test myproxy-init myproxy-get-delegation

default:	$(TARGETS)

gsi-socket-test: gsi_socket_test.o gsi_socket.o
	$(LINK) $(LDFLAGS) $(GLOBUS_GSSAPI_LDFLAGS) \
		-o $@ $^ $(GLOBUS_GSSAPI_LIBS)

gsi_socket.o: gsi_socket.c
	$(CC) $(GSI_SOCKET_CFLAGS) -c $<

myproxy-init: myproxy_init.o myproxy.o gsi_socket.o gnu_getopt.o gnu_getopt_long.o
	$(CC) $(LDFLAGS) $(GLOBUS_GSSAPI_LDFLAGS) \
		-o $@ $^ $(GLOBUS_GSSAPI_LIBS)

myproxy-get-delegation: myproxy_get_delegation.o myproxy.o gsi_socket.o gnu_getopt.o gnu_getopt_long.o
	$(CC) $(LDFLAGS) $(GLOBUS_GSSAPI_LDFLAGS) \
		-o $@ $^ $(GLOBUS_GSSAPI_LIBS)

myproxy.o: myproxy.c
	$(CC) $(GSI_SOCKET_CFLAGS) -c $<

gnu_getopt.o: gnu_getopt.c
	$(CC) -c $<

gnu_getopt_long.o: gnu_getopt_long.c
	$(CC) -c $<

clean:
	rm -f *.o
	rm -f $(TARGETS)
