include makefile_header

all: globus-xio-telnet globus-xio-email

globus-xio-email: globus_xio_email.c
	$(GLOBUS_CC) $(GLOBUS_CFLAGS) $(GLOBUS_INCLUDES) -o globus-xio-email \
        globus_xio_email.c $(GLOBUS_LDFLAGS) $(GLOBUS_LIBS) $(GLOBUS_PKG_LIBS)

globus-xio-telnet: globus_xio_telnet.c
	$(GLOBUS_CC) $(GLOBUS_CFLAGS) $(GLOBUS_INCLUDES) -o globus-xio-telnet \
        globus_xio_telnet.c $(GLOBUS_LDFLAGS) $(GLOBUS_LIBS) $(GLOBUS_PKG_LIBS)

clean:
	rm globus-xio-email globus-xio-telnet
