include makefile_header

all: globus-xio-telnet globus-xio-email globus-xio-udp-echo globus-xio-http-app

globus-xio-client: globus_xio_client.c
	$(GLOBUS_CC) $(GLOBUS_CFLAGS) $(GLOBUS_INCLUDES) -o globus-xio-client \
        globus_xio_client.c $(GLOBUS_LDFLAGS) $(GLOBUS_LIBS) $(GLOBUS_PKG_LIBS)

globus-xio-server: globus_xio_server.c
	$(GLOBUS_CC) $(GLOBUS_CFLAGS) $(GLOBUS_INCLUDES) -o globus-xio-server \
        globus_xio_server.c $(GLOBUS_LDFLAGS) $(GLOBUS_LIBS) $(GLOBUS_PKG_LIBS)

globus-xio-example: globus_xio_example.c
	$(GLOBUS_CC) $(GLOBUS_CFLAGS) $(GLOBUS_INCLUDES) -o globus-xio-example \
        globus_xio_example.c $(GLOBUS_LDFLAGS) $(GLOBUS_LIBS) $(GLOBUS_PKG_LIBS)

globus-xio-email: globus_xio_example.c
	$(GLOBUS_CC) $(GLOBUS_CFLAGS) $(GLOBUS_INCLUDES) -o globus-xio-example \
        globus_xio_example.c $(GLOBUS_LDFLAGS) $(GLOBUS_LIBS) $(GLOBUS_PKG_LIBS)

globus-xio-telnet: globus_xio_telnet.c
	$(GLOBUS_CC) $(GLOBUS_CFLAGS) $(GLOBUS_INCLUDES) -o globus-xio-telnet \
        globus_xio_telnet.c $(GLOBUS_LDFLAGS) $(GLOBUS_LIBS) $(GLOBUS_PKG_LIBS)

globus-xio-udp-echo: globus_xio_udp_echo.c
	$(GLOBUS_CC) $(GLOBUS_CFLAGS) $(GLOBUS_INCLUDES) -o globus-xio-udp-echo\
	globus_xio_udp_echo.c $(GLOBUS_LDFLAGS) $(GLOBUS_LIBS) $(GLOBUS_PKG_LIBS)

globus-xio-http-app: globus_xio_http_app.c
	$(GLOBUS_CC) $(GLOBUS_CFLAGS) $(GLOBUS_INCLUDES) -o globus-xio-http-app\
	globus_xio_http_app.c $(GLOBUS_LDFLAGS) $(GLOBUS_LIBS) $(GLOBUS_PKG_LIBS)

clean:
	rm globus-xio-email globus-xio-telnet globus-xio-udp-echo globus-xio-http-app globus-xio-server globus-xio-client
